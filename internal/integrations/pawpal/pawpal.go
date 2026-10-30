package pawpal

import (
	"crypto/subtle"
	"fmt"
)

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

func VerifyWebhook(providedKey, expectedKey []byte, payload any) WebhookVerification {
	if subtle.ConstantTimeCompare(providedKey, expectedKey) == 0 {
		return WebhookVerification{
			Outcome: WebhookUnauthorized,
		}
	}
	payloadRecord, valid := payload.(map[string]any)
	if !valid {
		return WebhookVerification{
			Outcome: WebhookUnauthorized,
		}
	}
	orderID, valid := payloadRecord["orderId"].(float64)
	if !valid {
		return WebhookVerification{
			Outcome: WebhookMalformed,
		}
	}
	if approved, valid := payloadRecord["status"]; !valid || approved != "approved" {
		return WebhookVerification{
			Outcome: WebhookMalformed,
		}
	}
	return WebhookVerification{Outcome: WebhookApproved, OrderID: int64(orderID)}
}
