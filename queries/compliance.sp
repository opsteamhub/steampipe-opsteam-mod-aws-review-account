
query "vpc_default_security_group_restricts_all_traffic" {
  title = "1.1 VPC default security group should not allow inbound and outbound traffic"
  sql = <<EOT
    select
    vpc_id resource,
    case
        when jsonb_array_length(ip_permissions) = 0
        and jsonb_array_length(ip_permissions_egress) = 0 then 'ok'
        else 'alarm'
    end status,
    case
        when jsonb_array_length(ip_permissions) > 0
        and jsonb_array_length(ip_permissions_egress) > 0 then 'Default security group ' || group_id || ' has inbound and outbound rules.'
        when jsonb_array_length(ip_permissions) > 0
        and jsonb_array_length(ip_permissions_egress) = 0 then 'Default security group ' || group_id || ' has inbound rules.'
        when jsonb_array_length(ip_permissions) = 0
        and jsonb_array_length(ip_permissions_egress) > 0 then 'Default security group ' || group_id || ' has outbound rules.'
        else 'Default security group ' || group_id || ' has no inbound or outbound rules.'
    end reason,
    region,
    account_id
    from
    aws_vpc_security_group
    where
    group_name = 'default';
    EOT
}    

#

query "iam_user_access_key_age_90" {
  title = "1.2 IAM user access keys should be rotated at least every 90 days"
  sql = <<EOT
    select
    user_name  as resource,
    case
        when create_date <= (current_date - interval '90' day) then 'alarm'
        else 'ok'
    end status,
    user_name || ' ' || access_key_id || ' created ' || to_char(create_date, 'DD-Mon-YYYY') || ' (' || extract(
        day
        from
        current_timestamp - create_date
    ) || ' days).' as reason,
    account_id
    from
    aws_iam_access_key;
    EOT
}    

query "iam_account_password_policy_strong_min_length_8" {
  title = "1.3 IAM users should have strong configurations with minimum length of 8"
  sql = <<EOT
    select
     a.account_id as resource,
    case
        when minimum_password_length >= 8
        and require_lowercase_characters = 'true'
        and require_uppercase_characters = 'true'
        and require_numbers = 'true'
        and require_symbols = 'true' then 'ok'
        else 'alarm'
    end as status,
    case
        when minimum_password_length is null then 'No password policy set.'
        when minimum_password_length >= 8
        and require_lowercase_characters = 'true'
        and require_uppercase_characters = 'true'
        and require_numbers = 'true'
        and require_symbols = 'true' then 'Strong password policies configured.'
        else 'Password policy ' || concat_ws(
        ', ',
        case
            when minimum_password_length < 8 then (
            'minimum password length set to ' || minimum_password_length
            )
        end,
        case
            when not (require_lowercase_characters = 'true') then 'lowercase characters not required'
        end,
        case
            when not (require_uppercase_characters = 'true') then 'uppercase characters not required'
        end,
        case
            when not (require_numbers) then 'numbers not required'
        end,
        case
            when not (require_symbols) then 'symbols not required'
        end
        ) || '.'
    end as reason,
    a.account_id
    from
    aws_account as a
    left join aws_iam_account_password_policy as pol on a.account_id = pol.account_id;
    EOT
} 

#

query "iam_root_user_hardware_mfa_enabled" {
  title = "1.4 IAM root user hardware MFA should be enabled"
  sql = <<EOT
    select
     s.account_id as resource,
    case
        when account_mfa_enabled
        and serial_number is null then 'ok'
        else 'alarm'
    end status,
    case
        when account_mfa_enabled = false then 'MFA not enabled for root account.'
        when serial_number is not null then 'MFA enabled for root account, but the MFA associated is a virtual device.'
        else 'Hardware MFA device enabled for root account.'
    end reason,
    s.account_id
    from
    aws_iam_account_summary as s
    left join aws_iam_virtual_mfa_device on serial_number = 'arn:' || s.partition || ':iam::' || s.account_id || ':mfa/root-account-mfa-device';
    EOT
} 

#

query "rds_db_instance_in_backup_plan" {
  title = "1.5 RDS DB instances should be in a backup plan"
  sql = <<EOT
    with mapped_with_id as (
    select
        jsonb_agg(elems) as mapped_ids
    from
        aws_backup_selection,
        jsonb_array_elements(resources) as elems
    group by
        backup_plan_id
    ),
    mapped_with_tags as (
    select
        jsonb_agg(elems ->> 'ConditionKey') as mapped_tags
    from
        aws_backup_selection,
        jsonb_array_elements(list_of_tags) as elems
    group by
        backup_plan_id
    ),
    backed_up_instance as (
    select
        i.db_instance_identifier
    from
        aws_rds_db_instance as i
        join mapped_with_id as t on t.mapped_ids ?| array [ i.arn ]
    union
    select
        i.db_instance_identifier
    from
        aws_rds_db_instance as i
        join mapped_with_tags as t on t.mapped_tags ?| array(
        select
            jsonb_object_keys(tags)
        )
    )
    select
    i.arn as resource,
    case
        when b.db_instance_identifier is null then 'alarm'
        else 'ok'
    end as status,
    case
        when b.db_instance_identifier is null then i.title || ' not in backup plan.'
        else i.title || ' in backup plan.'
    end as reason,
    i.region,
    i.account_id
    from
    aws_rds_db_instance as i
    left join backed_up_instance as b on i.db_instance_identifier = b.db_instance_identifier;
    EOT
} 

#

query "rds_db_instance_backup_enabled" {
  title = "1.6 RDS DB instance backup should be enabled"
  sql = <<EOT
    select
    arn as resource,
    case
        when backup_retention_period < 1 then 'alarm'
        else 'ok'
    end as status,
    case
        when backup_retention_period < 1 then title || ' backups not enabled.'
        else title || ' backups enabled.'
    end as reason,
    region,
    account_id
    from
    aws_rds_db_instance;
    EOT
} 

#

query "dynamodb_table_point_in_time_recovery_enabled" {
  title = "1.7 DynamoDB table point-in-time recovery should be enabled"
  sql = <<EOT
    select
    arn as resource,
    case
        when lower(
        point_in_time_recovery_description ->> 'PointInTimeRecoveryStatus'
        ) = 'disabled' then 'alarm'
        else 'ok'
    end as status,
    case
        when lower(
        point_in_time_recovery_description ->> 'PointInTimeRecoveryStatus'
        ) = 'disabled' then title || ' point-in-time recovery not enabled.'
        else title || ' point-in-time recovery enabled.'
    end as reason,
    region,
    account_id
    from
    aws_dynamodb_table;
    EOT
} 

#

query "dynamodb_table_in_backup_plan" {
  title = "1.8 DynamoDB tables should be in a backup plan"
  sql = <<EOT
    with mapped_with_id as (
    select
        jsonb_agg(elems) as mapped_ids
    from
        aws_backup_selection,
        jsonb_array_elements(resources) as elems
    group by
        backup_plan_id
    ),
    mapped_with_tags as (
    select
        jsonb_agg(elems ->> 'ConditionKey') as mapped_tags
    from
        aws_backup_selection,
        jsonb_array_elements(list_of_tags) as elems
    group by
        backup_plan_id
    ),
    backed_up_table as (
    select
        t.name
    from
        aws_dynamodb_table as t
        join mapped_with_id as m on m.mapped_ids ?| array [ t.arn ]
    union
    select
        t.name
    from
        aws_dynamodb_table as t
        join mapped_with_tags as m on m.mapped_tags ?| array(
        select
            jsonb_object_keys(tags)
        )
    )
    select
    t.arn as resource,
    case
        when b.name is null then 'alarm'
        else 'ok'
    end as status,
    case
        when b.name is null then t.title || ' not in backup plan.'
        else t.title || ' in backup plan.'
    end as reason,
    t.region,
    t.account_id
    from
    aws_dynamodb_table as t
    left join backed_up_table as b on t.name = b.name;
    EOT
} 

#

query "cloudtrail_multi_region_trail_enabled" {
  title = "1.9 At least one multi-region AWS CloudTrail should be present in an account"
  sql = <<EOT
    with multi_region_trails as (
    select
        account_id,
        count(account_id) as num_multregion_trails
    from
        aws_cloudtrail_trail
    where
        is_multi_region_trail
        and region = home_region
        and is_logging
    group by
        account_id,
        is_multi_region_trail
    ),
    organization_trails as (
    select
        is_organization_trail,
        is_logging,
        is_multi_region_trail,
        account_id
    from
        aws_cloudtrail_trail
    where
        is_organization_trail
    )
    select
    distinct a.arn as resource,
    case
        when coalesce(num_multregion_trails, 0) >= 1 then 'ok'
        when o.is_organization_trail
        and o.is_logging
        and o.is_multi_region_trail then 'ok'
        when o.is_organization_trail
        and o.is_multi_region_trail
        and o.is_logging is null then 'info'
        else 'alarm'
    end as status,
    case
        when coalesce(num_multregion_trails, 0) >= 1 then a.title || ' has ' || coalesce(num_multregion_trails, 0) || ' multi-region trail(s).'
        when o.is_organization_trail
        and o.is_logging
        and o.is_multi_region_trail then a.title || ' has multi-region trail(s).'
        when o.is_organization_trail
        and o.is_multi_region_trail
        and o.is_logging is null then a.title || ' has organization trail, check organization account for cloudtrail logging status.'
        else a.title || ' does not have multi-region trail(s).'
    end as reason,
    a.account_id
    from
    aws_account as a
    left join multi_region_trails as b on a.account_id = b.account_id
    left join organization_trails as o on a.account_id = o.account_id;
    EOT
} 

#

query "cloudtrail_trail_enabled" {
  title = "1.10 At least one enabled trail should be present in a region"
  sql = <<EOT
    with trails_enabled as (
    select
        arn,
        is_logging
    from
        aws_cloudtrail_trail
    where
        home_region = region
    )
    select
    a.arn as resource,
    case
        when b.is_logging is null
        and a.is_logging then 'ok'
        when b.is_logging then 'ok'
        else 'alarm'
    end as status,
    case
        when b.is_logging is null
        and a.is_logging then a.title || ' enabled.'
        when b.is_logging then a.title || ' enabled.'
        else a.title || ' disabled.'
    end as reason,
    a.region,
    a.account_id
    from
    aws_cloudtrail_trail as a
    left join trails_enabled b on a.arn = b.arn;
    EOT
} 

#

query "ec2_ebs_default_encryption_enabled" {
  title = "1.11 EBS default encryption should be enabled"
  sql = <<EOT
    select
    'arn:' || partition || '::' || region || ':' || account_id as resource,
    case
        when not default_ebs_encryption_enabled then 'alarm'
        else 'ok'
    end as status,
    case
        when not default_ebs_encryption_enabled then region || ' default EBS encryption disabled.'
        else region || ' default EBS encryption enabled.'
    end as reason,
    region,
    account_id
    from
    aws_ec2_regional_settings;
    EOT
} 

#

query "vpc_network_acl_unused" {
  title = "1.12 VPC network access query lists (network ACLs) should be associated with a subnet"
  sql = <<EOT
    select
    network_acl_id as resource,
    case
        when jsonb_array_length(associations) >= 1 then 'ok'
        else 'alarm'
    end status,
    case
        when jsonb_array_length(associations) >= 1 then title || ' associated with subnet.'
        else title || ' not associated with subnet.'
    end reason,
    region,
    account_id
    from
    aws_vpc_network_acl;
    EOT
}

#

query "vpc_security_group_associated_to_eni" {
  title = "1.13 VPC security groups should be associated with at least one ENI"
  sql = <<EOT
    select
    network_acl_id as resource,
    case
        when jsonb_array_length(associations) >= 1 then 'ok'
        else 'alarm'
    end status,
    case
        when jsonb_array_length(associations) >= 1 then title || ' associated with subnet.'
        else title || ' not associated with subnet.'
    end reason,
    region,
    account_id
    from
    aws_vpc_network_acl;
    EOT
}

#

query "cloudtrail_trail_logs_encrypted_with_kms_cmk" {
  title = "1.14 CloudTrail trail logs should be encrypted with KMS CMK"
  sql = <<EOT
    select
    arn as resource,
    case
        when kms_key_id is null then 'alarm'
        else 'ok'
    end as status,
    case
        when kms_key_id is null then title || ' logs are not encrypted at rest.'
        else title || ' logs are encrypted at rest.'
    end as reason,
    region,
    account_id
    from
    aws_cloudtrail_trail
    where
    region = home_region;
    EOT
}

#CloudTrail trail log file validation should be enabled

query "cloudtrail_trail_validation_enabled" {
  title = "1.15 CloudTrail trail log file validation should be enabled"
  sql = <<EOT
    select
    arn as resource,
    case
        when log_file_validation_enabled then 'ok'
        else 'alarm'
    end as status,
    case
        when log_file_validation_enabled then title || ' log file validation enabled.'
        else title || ' log file validation disabled.'
    end as reason,
    region,
    account_id
    from
    aws_cloudtrail_trail
    where
    region = home_region;
    EOT
}

#

query "eks_cluster_no_default_vpc" {
  title = "1.16 EKS clusters should not be configured within a default VPC"
  sql = <<EOT
    with default_vpc_cluster as (
    select
        distinct c.arn
    from
        aws_eks_cluster as c
        left join aws_vpc as v on v.vpc_id = c.resources_vpc_config ->> 'VpcId'
    where
        v.is_default
    )
    select
    c.arn as resource,
    case
        when v.arn is not null then 'alarm'
        else 'ok'
    end as status,
    case
        when v.arn is not null then title || ' uses default VPC.'
        else title || ' does not use default VPC.'
    end as reason,
    c.region,
    c.account_id
    from
    aws_eks_cluster as c
    left join default_vpc_cluster as v on v.arn = c.arn;
    EOT
}

#

query "eks_cluster_no_multiple_security_groups" {
  title = "1.17 EKS clusters should not use multiple security groups"
  sql = <<EOT
    select
    arn as resource,
    case
        when jsonb_array_length(resources_vpc_config -> 'SecurityGroupIds') > 1 then 'alarm'
        else 'ok'
    end as status,
    title || ' has ' || jsonb_array_length(resources_vpc_config -> 'SecurityGroupIds') || ' security group(s).' as reason,
    region,
    account_id
    from
    aws_eks_cluster;
    EOT
}

#

query "elb_application_lb_redirect_http_request_to_https" {
  title = "1.18 Application Load Balancer should be configured to redirect all HTTP requests to HTTPS "
  sql = <<EOT
    with detailed_listeners as (
    select
        arn,
        load_balancer_arn,
        protocol
    from
        aws_ec2_load_balancer_listener,
        jsonb_array_elements(default_actions) as ac
    where
        split_part(arn, '/', 2) = 'app'
        and protocol = 'HTTP'
        and ac ->> 'Type' = 'redirect'
        and ac -> 'RedirectConfig' ->> 'Protocol' = 'HTTPS'
    )
    select
    a.arn as resource,
    case
        when b.load_balancer_arn is null then 'alarm'
        else 'ok'
    end as status,
    case
        when b.load_balancer_arn is not null then a.title || ' associated with HTTP redirection.'
        else a.title || ' not associated with HTTP redirection.'
    end as reason,
    a.region,
    a.account_id
    from
    aws_ec2_application_load_balancer a
    left join detailed_listeners b on a.arn = b.load_balancer_arn;
    EOT
}

#

query "kms_key_decryption_restricted_in_iam_customer_managed_policy" {
  title = "1.19 IAM customer managed policies should not allow decryption actions on all KMS keys"
  sql = <<EOT
    with policy_with_decrypt_grant as (
    select
        distinct arn
    from
        aws_iam_policy,
        jsonb_array_elements(policy_std -> 'Statement') as statement
    where
        not is_aws_managed
        and statement ->> 'Effect' = 'Allow'
        and statement -> 'Resource' ?| array [ '*',
        'arn:aws:kms:*:' || account_id || ':key/*',
        'arn:aws:kms:*:' || account_id || ':alias/*' ]
        and statement -> 'Action' ?| array [ '*',
        'kms:*',
        'kms:decrypt',
        'kms:reencryptfrom',
        'kms:reencrypt*' ]
    )
    select
    i.arn as resource,
    case
        when d.arn is null then 'ok'
        else 'alarm'
    end as status,
    case
        when d.arn is null then i.title || ' doesn''t allow decryption actions on all keys.'
        else i.title || ' allows decryption actions on all keys.'
    end as reason,
    i.account_id
    from
    aws_iam_policy i
    left join policy_with_decrypt_grant d on i.arn = d.arn
    where
    not is_aws_managed;
    EOT
}

#

query "lambda_function_use_latest_runtime" {
  title = "1.20 Lambda functions should use latest runtimes"
  sql = <<EOT
    select
    arn as resource,
    case
        when package_type <> 'Zip' then 'skip'
        when runtime in (
        'nodejs18.x',
        'nodejs16.x',
        'nodejs14.x',
        'python3.10',
        'python3.9',
        'python3.8',
        'python3.7',
        'ruby3.2',
        'ruby2.7',
        'java17',
        'java11',
        'java8',
        'java8.al2',
        'go1.x',
        'dotnet7',
        'dotnet6'
        ) then 'ok'
        else 'alarm'
    end as status,
    case
        when package_type <> 'Zip' then title || ' package type is ' || package_type || '.'
        when runtime in (
        'nodejs18.x',
        'nodejs16.x',
        'nodejs14.x',
        'python3.10',
        'python3.9',
        'python3.8',
        'python3.7',
        'ruby3.2',
        'ruby2.7',
        'java17',
        'java11',
        'java8',
        'java8.al2',
        'go1.x',
        'dotnet7',
        'dotnet6'
        ) then title || ' uses latest runtime - ' || runtime || '.'
        else title || ' uses ' || runtime || ' which is not the latest version.'
    end as reason,
    region,
    account_id
    from
    aws_lambda_function;
    EOT
}
#

query "sns_topic_encrypted_at_rest" {
  title = "1.21 SNS topics should be encrypted at rest using AWS KMS"
  sql = <<EOT
    select
    topic_arn as resource,
    case
        when kms_master_key_id is null then 'alarm'
        else 'ok'
    end as status,
    case
        when kms_master_key_id is null then title || ' encryption at rest disabled.'
        else title || ' encryption at rest enabled.'
    end as reason,
    region,
    account_id
    from
    aws_sns_topic;
    EOT
}

#

query "sqs_queue_encrypted_at_rest" {
  title = "1.22 Amazon SQS queues should be encrypted at rest"
  sql = <<EOT
    select
    queue_arn as resource,
    case
        when kms_master_key_id is null then 'alarm'
        else 'ok'
    end as status,
    case
        when kms_master_key_id is null then title || ' encryption at rest disabled.'
        else title || ' encryption at rest enabled.'
    end as reason,
    region,
    account_id
    from
    aws_sqs_queue;
    EOT
}