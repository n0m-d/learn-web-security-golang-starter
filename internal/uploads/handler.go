package uploads

import (
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"path/filepath"

	"github.com/bootdotdev/learn-web-security/internal/accounts"
	"github.com/bootdotdev/learn-web-security/internal/auth/sessions"
	"github.com/bootdotdev/learn-web-security/internal/httpx"
	"github.com/bootdotdev/learn-web-security/internal/logging"
	"github.com/bootdotdev/learn-web-security/internal/templates"
)

type taxExemptionPage struct {
	templates.Page
	DisplayName string
	Files       []File
	Error       string
}

type Handler struct {
	accountStore    *accounts.Store
	store           *Store
	renderer        *templates.Renderer
	logger          *logging.Logger
	uploadDirectory string
	maxUploadBytes  int64
}

func NewHandler(accountStore *accounts.Store, store *Store, renderer *templates.Renderer, logger *logging.Logger, uploadDirectory string, maxUploadBytes int64) *Handler {
	return &Handler{
		accountStore: accountStore, store: store, renderer: renderer, logger: logger,
		uploadDirectory: uploadDirectory, maxUploadBytes: maxUploadBytes,
	}
}

func (handler *Handler) TaxExemptionPage(responseWriter http.ResponseWriter, request *http.Request) {
	current, ok := handler.requireAuth(responseWriter, request)
	if !ok {
		return
	}
	handler.renderTaxExemption(responseWriter, request, http.StatusOK, current, "")
}

func (handler *Handler) Upload(responseWriter http.ResponseWriter, request *http.Request) {
	current, ok := handler.requireAuth(responseWriter, request)
	if !ok {
		return
	}
	contents, originalName, contentType, err := handler.readUpload(responseWriter, request)
	if err != nil {
		if errors.Is(err, errUploadTooLarge) {
			handler.errorPage(responseWriter, http.StatusRequestEntityTooLarge, "Content Too Large", "The submitted request exceeds the allowed size.")
			return
		}
		handler.renderTaxExemption(responseWriter, request, http.StatusBadRequest, current, "Choose a PDF, JPEG, PNG, or WebP file to upload.")
		return
	}
	document, err := StoreDocument(contents, originalName, contentType, handler.uploadDirectory)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	uploadedFile, err := handler.store.Create(request.Context(), current.User.ID, originalName, document)
	if err != nil {
		_ = RemoveDocument(document.StoragePath)
		handler.internalError(responseWriter, request, err)
		return
	}
	_ = handler.logger.Event("tax_exemption_uploaded", map[string]any{
		"userId": current.User.ID, "email": current.User.Email, "uploadedFileId": uploadedFile.ID,
		"originalName": originalName, "contentType": document.ContentType, "storagePath": document.StoragePath, "size": len(contents),
	})
	http.Redirect(responseWriter, request, "/account/tax-exemption", http.StatusFound)
}

func (handler *Handler) Download(responseWriter http.ResponseWriter, request *http.Request) {
	current, ok := handler.requireAuth(responseWriter, request)
	if !ok {
		return
	}
	fileID, valid := httpx.ParseSafeInteger(request.PathValue("id"))
	if !valid {
		handler.fileNotFound(responseWriter)
		return
	}
	file, found, err := handler.store.FindByID(request.Context(), fileID)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	if !found || (current.User.Role != "support" && current.User.Role != "admin" && file.UserID != current.User.ID) {
		handler.fileNotFound(responseWriter)
		return
	}
	handler.serveDocument(responseWriter, request, file.OriginalName, file.ContentType, file.StoragePath)
}

func (handler *Handler) ImportedDownload(responseWriter http.ResponseWriter, request *http.Request) {
	current, ok := handler.requireAuth(responseWriter, request)
	if !ok {
		return
	}
	if current.User.Role != "support" && current.User.Role != "admin" {
		handler.errorPage(responseWriter, http.StatusForbidden, "Forbidden", "You don't have permission to view this page.")
		return
	}
	documentID, valid := httpx.ParseSafeInteger(request.PathValue("id"))
	if !valid {
		handler.fileNotFound(responseWriter)
		return
	}
	document, found, err := handler.store.FindImportedByID(request.Context(), documentID)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	if !found {
		handler.fileNotFound(responseWriter)
		return
	}
	handler.serveDocument(responseWriter, request, document.OriginalName, document.ContentType, document.StoragePath)
}

var errUploadTooLarge = errors.New("document upload is too large")

func (handler *Handler) readUpload(responseWriter http.ResponseWriter, request *http.Request) ([]byte, string, string, error) {
	request.Body = http.MaxBytesReader(responseWriter, request.Body, handler.maxUploadBytes+1024*1024)
	if err := request.ParseMultipartForm(handler.maxUploadBytes); err != nil {
		if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
			return nil, "", "", errUploadTooLarge
		}
		return nil, "", "", err
	}
	files := request.MultipartForm.File["document"]
	if len(files) == 0 {
		return nil, "", "", errors.New("missing document upload")
	}
	file, err := files[0].Open()
	if err != nil {
		return nil, "", "", fmt.Errorf("open document upload: %w", err)
	}
	defer file.Close()
	contents, err := io.ReadAll(io.LimitReader(file, handler.maxUploadBytes+1))
	if err != nil {
		return nil, "", "", fmt.Errorf("read document upload: %w", err)
	}
	if int64(len(contents)) > handler.maxUploadBytes {
		return nil, "", "", errUploadTooLarge
	}
	return contents, filepath.Base(files[0].Filename), files[0].Header.Get("Content-Type"), nil
}

func (handler *Handler) serveDocument(responseWriter http.ResponseWriter, request *http.Request, originalName, contentType, storagePath string) {
	contents, err := ReadDocument(storagePath)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	responseWriter.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": originalName}))
	responseWriter.Header().Set("Content-Type", contentType)
	responseWriter.WriteHeader(http.StatusOK)
	if _, err := responseWriter.Write(contents); err != nil {
		_ = handler.logger.Event("unhandled_error", map[string]any{"method": request.Method, "path": request.URL.Path, "message": err.Error()})
	}
}

func (handler *Handler) renderTaxExemption(responseWriter http.ResponseWriter, request *http.Request, statusCode int, current accounts.CurrentSession, errorMessage string) {
	files, err := handler.store.ListForUser(request.Context(), current.User.ID)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	if err := handler.renderer.Render(responseWriter, statusCode, "tax-exemption", taxExemptionPage{
		Title: "Tax Exemption Documents", DisplayName: current.User.DisplayName, Files: files, Error: errorMessage,
	}); err != nil {
		handler.internalError(responseWriter, request, err)
	}
}

func (handler *Handler) requireAuth(responseWriter http.ResponseWriter, request *http.Request) (accounts.CurrentSession, bool) {
	current, found, err := sessions.Require(responseWriter, request, handler.accountStore)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return accounts.CurrentSession{}, false
	}
	return current, found
}

func (handler *Handler) fileNotFound(responseWriter http.ResponseWriter) {
	handler.errorPage(responseWriter, http.StatusNotFound, "File Not Found", "We couldn't find that file.")
}

func (handler *Handler) errorPage(responseWriter http.ResponseWriter, statusCode int, title, message string) {
	if err := httpx.RespondWithErrorPage(responseWriter, handler.renderer, statusCode, title, message); err != nil {
		http.Error(responseWriter, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
}

func (handler *Handler) internalError(responseWriter http.ResponseWriter, request *http.Request, err error) {
	_ = handler.logger.Event("unhandled_error", map[string]any{"method": request.Method, "path": request.URL.Path, "message": err.Error()})
	handler.errorPage(responseWriter, http.StatusInternalServerError, "Unhandled Error", err.Error())
}
