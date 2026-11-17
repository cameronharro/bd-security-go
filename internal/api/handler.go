package api

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/bootdotdev/learn-web-security/internal/accounts"
	"github.com/bootdotdev/learn-web-security/internal/auth/sessions"
	"github.com/bootdotdev/learn-web-security/internal/httpx"
	"github.com/bootdotdev/learn-web-security/internal/logging"
	"github.com/bootdotdev/learn-web-security/internal/orders"
	"github.com/bootdotdev/learn-web-security/internal/storefront"
)

type integrationOrderResponse struct {
	ID         int64  `json:"id"`
	Status     string `json:"status"`
	TotalCents int64  `json:"total_cents"`
	CreatedAt  string `json:"created_at"`
}

type orderItemResponse struct {
	ProductID   int64  `json:"product_id"`
	ProductName string `json:"product_name"`
	Quantity    int64  `json:"quantity"`
	PriceCents  int64  `json:"price_cents"`
}

func toOrderItemResponse(item orders.Item) orderItemResponse {
	return orderItemResponse{
		ProductID:   item.ProductID,
		ProductName: item.ProductName,
		Quantity:    item.Quantity,
		PriceCents:  item.PriceCents,
	}
}

type Handler struct {
	accountStore      *accounts.Store
	orderStore        *orders.Store
	productStore      *storefront.Store
	apiStore          *Store
	logger            *logging.Logger
	maxProductResults int64
}

func NewHandler(accountStore *accounts.Store, orderStore *orders.Store, productStore *storefront.Store, apiStore *Store, logger *logging.Logger, maxProductResults int) *Handler {
	return &Handler{
		accountStore: accountStore, orderStore: orderStore, productStore: productStore, apiStore: apiStore,
		logger: logger, maxProductResults: int64(maxProductResults),
	}
}

func convertSlice[E, V any](slice []E, converter func(E) V) []V {
	result := make([]V, len(slice))
	for i, e := range slice {
		result[i] = converter(e)
	}
	return result
}

type orderResponse struct {
	Id         int64  `json:"id"`
	Status     string `json:"status"`
	TotalCents int64  `json:"total_cents"`
	CreatedAt  string `json:"created_at"`
}

func toOrderResponse(order orders.Order) orderResponse {
	return orderResponse{
		Id:         order.ID,
		Status:     order.Status,
		TotalCents: order.TotalCents,
		CreatedAt:  order.CreatedAt,
	}
}

func (handler *Handler) AccountOrders(responseWriter http.ResponseWriter, request *http.Request) {
	current, ok := handler.requireAuthentication(responseWriter, request)
	if !ok {
		return
	}
	orders, err := handler.orderStore.ListForUser(request.Context(), current.User.ID)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	ordersResponse := convertSlice(orders, toOrderResponse)
	httpx.RespondWithJSON(responseWriter, http.StatusOK, map[string]any{"orders": ordersResponse})
}

func (handler *Handler) Order(responseWriter http.ResponseWriter, request *http.Request) {
	current, ok := handler.requireAuthentication(responseWriter, request)
	if !ok {
		return
	}
	orderID, valid := httpx.ParseSafeInteger(request.PathValue("id"))
	if !valid {
		httpx.RespondWithJSON(responseWriter, http.StatusNotFound, map[string]string{"error": "Order not found"})
		return
	}
	order, found, err := handler.orderStore.FindByID(request.Context(), orderID)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	if !found || current.User.ID != order.UserID {
		httpx.RespondWithJSON(responseWriter, http.StatusNotFound, map[string]string{"error": "Order not found"})
		return
	}
	items, err := handler.orderStore.ListItems(request.Context(), order.ID)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	orderResponse := toOrderResponse(order)
	itemResponses := convertSlice(items, toOrderItemResponse)
	httpx.RespondWithJSON(responseWriter, http.StatusOK, map[string]any{"order": orderResponse, "items": itemResponses})
}

type productResponse struct {
	Id          int64  `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	ImagePath   string `json:"image_path"`
	PriceCents  int64  `json:"price_cents"`
}

func toProductResponse(product storefront.Product) productResponse {
	return productResponse{
		Id:          product.ID,
		Name:        product.Name,
		Description: product.Description,
		ImagePath:   product.ImagePath,
		PriceCents:  product.PriceCents,
	}
}

func (handler *Handler) Products(responseWriter http.ResponseWriter, request *http.Request) {
	products, err := handler.productStore.ListProducts(request.Context(), handler.maxProductResults)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	respProducts := convertSlice(products, toProductResponse)
	httpx.RespondWithJSON(responseWriter, http.StatusOK, map[string]any{"products": respProducts})
}

func (handler *Handler) WarehouseOrders(responseWriter http.ResponseWriter, request *http.Request) {
	apiKey, found, err := handler.apiStore.FindKey(request.Context(), request.Header.Get("X-API-Key"))
	if err != nil || !found {
		httpx.RespondWithJSON(responseWriter, http.StatusUnauthorized, map[string]any{"message": "Missing or invalid API Key"})
		return
	}
	requiredScope := "orders:read"
	if !strings.Contains(apiKey.Scope, requiredScope) {
		httpx.RespondWithJSON(responseWriter, http.StatusForbidden, map[string]any{"message": fmt.Sprintf("API Key lacks necessary scope: %s", requiredScope)})
		return
	}
	quota, err := handler.apiStore.ConsumeQuota(request.Context(), apiKey.ID)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	if !quota.Allowed {
		RespondWithQuotaExhausted(responseWriter, quota)
		return
	}
	SetQuotaHeaders(responseWriter, quota)
	orders, err := handler.orderStore.ListAll(request.Context())
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	responses := make([]integrationOrderResponse, 0, len(orders))
	for _, order := range orders {
		responses = append(responses, integrationOrderResponse{
			ID: order.ID, Status: order.Status, TotalCents: order.TotalCents, CreatedAt: order.CreatedAt,
		})
	}
	httpx.RespondWithJSON(responseWriter, http.StatusOK, map[string]any{
		"integration": "Warehouse Fulfillment Integration",
		"orders":      responses,
		"quota":       ToQuotaResponse(quota),
	})
}

func (handler *Handler) requireAuthentication(responseWriter http.ResponseWriter, request *http.Request) (accounts.CurrentSession, bool) {
	current, found, err := sessions.Current(request, handler.accountStore)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return accounts.CurrentSession{}, false
	}
	if !found {
		httpx.RespondWithJSON(responseWriter, http.StatusUnauthorized, map[string]string{"error": "Authentication required"})
		return accounts.CurrentSession{}, false
	}
	return current, true
}

func (handler *Handler) internalError(responseWriter http.ResponseWriter, request *http.Request, err error) {
	_ = handler.logger.Event("unhandled_error", map[string]any{"method": request.Method, "path": request.URL.Path, "message": err.Error()})
	httpx.RespondWithError(responseWriter, http.StatusInternalServerError, err.Error())
}
