 query "account_count" {
  sql = <<-EOQ
    select
      count(*) as "Accounts"
    from
      aws_account;
  EOQ
}

query "account_table" {
  sql = <<-EOQ
    select
      account_id as "Account ID",
      account_aliases ->> 0 as "Alias",
      organization_id as "Organization ID",
      organization_master_account_email as "Organization Master Account Email",
      organization_master_account_id as "Organization Master Account ID",
      arn as "ARN"
    from
      aws_account;
  EOQ
}
