package pawpal

import (
	"crypto/subtle"
	"fmt"
	"math"
)

const maxSafeInteger = 9_007_199_254_740_991

type WebhookOutcome string

const (
	WebhookUnauthorized WebhookOutcome = "unauthorized"
	WebhookMalformed    WebhookOutcome = "malformed"
	WebhookApproved     WebhookOutcome = "approved"
)

type WebhookVerification struct {
	Outcome WebhookOutcome
	OrderID int64
}

func CreateCheckoutURL(orderID int64) string {
	return fmt.Sprintf("https://pawpal.example/checkout?orderId=%d", orderID)
}

func VerifyWebhook(providedKey, expectedKey string, payload any) WebhookVerification {
	if !webhookKeysMatch(providedKey, expectedKey) {
		return WebhookVerification{Outcome: WebhookUnauthorized}
	}
	return verifyPayload(payload)
}

func webhookKeysMatch(providedKey, expectedKey string) bool {
	providedBytes := []byte(providedKey)
	expectedBytes := []byte(expectedKey)
	return len(providedBytes) == len(expectedBytes) && subtle.ConstantTimeCompare(providedBytes, expectedBytes) == 1
}

func verifyPayload(payload any) WebhookVerification {
	payloadRecord, ok := payload.(map[string]any)
	if !ok {
		return WebhookVerification{Outcome: WebhookMalformed}
	}
	orderID, ok := payloadRecord["orderId"].(float64)
	if !ok || orderID != math.Trunc(orderID) || orderID <= 0 || orderID > maxSafeInteger || payloadRecord["status"] != "approved" {
		return WebhookVerification{Outcome: WebhookMalformed}
	}
	return WebhookVerification{Outcome: WebhookApproved, OrderID: int64(orderID)}
}
