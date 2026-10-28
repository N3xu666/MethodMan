variable "cloudflare_api_token" {
  type        = string
  sensitive   = true
  description = "Cloudflare API token (Pages:Edit, Account:Read)"
}

variable "cloudflare_account_id" {
  type        = string
  description = "Cloudflare account ID (from dashboard URL)"
}
