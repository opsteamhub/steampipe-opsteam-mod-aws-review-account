control "vpc_security_group_allows_ingress_to_cassandra_ports" {
  title = "3.1 VPC security groups should restrict ingress from 0.0.0.0/0 or ::/0 to cassandra ports 7199 or 9160 or 8888"
  severity = "high"
  sql = <<EOT
    with ingress_ssh_rules as (
    select
        group_id,
        count(*) as num_ssh_rules
    from
        aws_vpc_security_group_rule
    where
        type = 'ingress'
        and cidr_ipv4 = '0.0.0.0/0'
        and (
        (
            ip_protocol = '-1'
            and from_port is null
        )
        or (
            from_port >= 7199
            and to_port <= 7199
        )
        or (
            from_port >= 9160
            and to_port <= 9160
        )
        or (
            from_port >= 8888
            and to_port <= 8888
        )
        )
    group by
        group_id
    )
    select
    arn as resource,
    case
        when ingress_ssh_rules.group_id is null then 'ok'
        else 'alarm'
    end as status,
    case
        when ingress_ssh_rules.group_id is null then sg.group_id || ' ingress restricted for cassandra ports from 0.0.0.0/0.'
        else sg.group_id || ' contains ' || ingress_ssh_rules.num_ssh_rules || ' ingress rule(s) allowing access for cassandra ports from 0.0.0.0/0.'
    end as reason,
    sg.region,
    sg.account_id
    from
    aws_vpc_security_group as sg
    left join ingress_ssh_rules on ingress_ssh_rules.group_id = sg.group_id;
    EOT
}    

control "vpc_security_group_allows_ingress_to_memcached_port" {
  title = "3.2 VPC security groups should restrict ingress from 0.0.0.0/0 or ::/0 to memcached port 11211"
  severity = "high"
  sql = <<EOT
    with ingress_ssh_rules as (
    select
        group_id,
        count(*) as num_ssh_rules
    from
        aws_vpc_security_group_rule
    where
        type = 'ingress'
        and cidr_ipv4 = '0.0.0.0/0'
        and (
        (
            ip_protocol = '-1'
            and from_port is null
        )
        or (
            from_port >= 11211
            and to_port <= 11211
        )
        )
    group by
        group_id
    )
    select
    arn as resource,
    case
        when ingress_ssh_rules.group_id is null then 'ok'
        else 'alarm'
    end as status,
    case
        when ingress_ssh_rules.group_id is null then sg.group_id || ' ingress restricted for memcached port from 0.0.0.0/0.'
        else sg.group_id || ' contains ' || ingress_ssh_rules.num_ssh_rules || ' ingress rule(s) allowing access for memcached port from 0.0.0.0/0.'
    end as reason,
    sg.region,
    sg.account_id
    from
    aws_vpc_security_group as sg
    left join ingress_ssh_rules on ingress_ssh_rules.group_id = sg.group_id;
    EOT
}   

control "vpc_security_group_allows_ingress_to_mongodb_ports" {
  title = "3.3 VPC security groups should restrict ingress from 0.0.0.0/0 or ::/0 to mongoDB ports 27017 and 27018"
  severity = "high"
  sql = <<EOT
    with ingress_ssh_rules as (
    select
        group_id,
        count(*) as num_ssh_rules
    from
        aws_vpc_security_group_rule
    where
        type = 'ingress'
        and cidr_ipv4 = '0.0.0.0/0'
        and (
        (
            ip_protocol = '-1'
            and from_port is null
        )
        or (
            from_port >= 27017
            and to_port <= 27017
        )
        or (
            from_port >= 27018
            and to_port <= 27018
        )
        )
    group by
        group_id
    )
    select
    arn as resource,
    case
        when ingress_ssh_rules.group_id is null then 'ok'
        else 'alarm'
    end as status,
    case
        when ingress_ssh_rules.group_id is null then sg.group_id || ' ingress restricted for mongodb ports from 0.0.0.0/0.'
        else sg.group_id || ' contains ' || ingress_ssh_rules.num_ssh_rules || ' ingress rule(s) allowing access for mongodb ports from 0.0.0.0/0.'
    end as reason,
    sg.region,
    sg.account_id
    from
    aws_vpc_security_group as sg
    left join ingress_ssh_rules on ingress_ssh_rules.group_id = sg.group_id;
    EOT
}   

#

control "vpc_security_group_allows_ingress_to_oracle_ports" {
  title = "3.4 VPC security groups should restrict ingress from 0.0.0.0/0 or ::/0 to oracle ports 1521 or 2483"
  severity = "high"
  sql = <<EOT
    with ingress_ssh_rules as (
    select
        group_id,
        count(*) as num_ssh_rules
    from
        aws_vpc_security_group_rule
    where
        type = 'ingress'
        and cidr_ipv4 = '0.0.0.0/0'
        and (
        (
            ip_protocol = '-1'
            and from_port is null
        )
        or (
            from_port >= 1521
            and to_port <= 1521
        )
        or (
            from_port >= 2483
            and to_port <= 2483
        )
        )
    group by
        group_id
    )
    select
    arn as resource,
    case
        when ingress_ssh_rules.group_id is null then 'ok'
        else 'alarm'
    end as status,
    case
        when ingress_ssh_rules.group_id is null then sg.group_id || ' ingress restricted for oracle ports from 0.0.0.0/0.'
        else sg.group_id || ' contains ' || ingress_ssh_rules.num_ssh_rules || ' ingress rule(s) allowing access for oracle ports from 0.0.0.0/0.'
    end as reason,
    sg.region,
    sg.account_id
    from
    aws_vpc_security_group as sg
    left join ingress_ssh_rules on ingress_ssh_rules.group_id = sg.group_id;
    EOT
}   

#

control "vpc_security_group_restrict_ingress_kafka_port" {
  title = "3.5 VPC security groups should restrict ingress Kafka port access from 0.0.0.0/0"
  sql = <<EOT
    with ingress_kafka_port as (
    select
        group_id,
        count(*) as num_ssh_rules
    from
        aws_vpc_security_group_rule
    where
        type = 'ingress'
        and (
        cidr_ipv4 = '0.0.0.0/0'
        or cidr_ipv6 = '::/0'
        )
        and (
        (
            ip_protocol = '-1'
            and from_port is null
        )
        or (
            from_port >= 9092
            and to_port <= 9092
        )
        )
    group by
        group_id
    )
    select
    arn as resource,
    case
        when k.group_id is null then 'ok'
        else 'alarm'
    end as status,
    case
        when k.group_id is null then sg.group_id || ' ingress restricted for kafka port from 0.0.0.0/0.'
        else sg.group_id || ' contains ' || k.num_ssh_rules || ' ingress rule(s) allowing kafka port from 0.0.0.0/0.'
    end as reason,
    sg.region,
    sg.account_id
    from
    aws_vpc_security_group as sg
    left join ingress_kafka_port as k on k.group_id = sg.group_id;
    EOT
}   

#

control "vpc_security_group_restrict_ingress_redis_port" {
  title = "3.6 VPC security groups should restrict ingress redis access from 0.0.0.0/0"
  severity = "high"
  sql = <<EOT
    with ingress_redis_port as (
    select
        group_id,
        count(*) as num_redis_rules
    from
        aws_vpc_security_group_rule
    where
        type = 'ingress'
        and (
        cidr_ipv4 = '0.0.0.0/0'
        or cidr_ipv6 = '::/0'
        )
        and (
        (
            ip_protocol = '-1'
            and from_port is null
        )
        or (
            from_port >= 6379
            and to_port <= 6379
        )
        )
    group by
        group_id
    )
    select
    arn as resource,
    case
        when ingress_redis_port.group_id is null then 'ok'
        else 'alarm'
    end as status,
    case
        when ingress_redis_port.group_id is null then sg.group_id || ' restricted ingress from 0.0.0.0/0 or ::/0 to Redis port 6379.'
        else sg.group_id || ' contains ' || ingress_redis_port.num_redis_rules || ' ingress rule(s) from 0.0.0.0/0 or ::/0 to Redis port 6379.'
    end as reason,
    region,
    account_id
    from
    aws_vpc_security_group as sg
    left join ingress_redis_port on ingress_redis_port.group_id = sg.group_id;
    EOT
}   

#

control "vpc_security_group_restrict_ingress_ssh_all" {
  title = "3.7 VPC security groups should restrict ingress SSH access from 0.0.0.0/0"
  severity = "high"
  sql = <<EOT
    with ingress_ssh_rules as (
    select
        group_id,
        count(*) as num_ssh_rules
    from
        aws_vpc_security_group_rule
    where
        type = 'ingress'
        and cidr_ipv4 = '0.0.0.0/0'
        and (
        (
            ip_protocol = '-1'
            and from_port is null
        )
        or (
            from_port >= 22
            and to_port <= 22
        )
        )
    group by
        group_id
    )
    select
    arn as resource,
    case
        when ingress_ssh_rules.group_id is null then 'ok'
        else 'alarm'
    end as status,
    case
        when ingress_ssh_rules.group_id is null then sg.group_id || ' ingress restricted for SSH from 0.0.0.0/0.'
        else sg.group_id || ' contains ' || ingress_ssh_rules.num_ssh_rules || ' ingress rule(s) allowing SSH from 0.0.0.0/0.'
    end as reason,
    region,
    account_id
    from
    aws_vpc_security_group as sg
    left join ingress_ssh_rules on ingress_ssh_rules.group_id = sg.group_id;
    EOT
}   

#

control "vpc_security_group_restrict_ingress_rdp_all" {
  title = "3.8 VPC security groups should restrict ingress RDP access from 0.0.0.0/0"
  severity = "critical"
  sql = <<EOT
    with ingress_ssh_rules as (
    select
        group_id,
        count(*) as num_ssh_rules
    from
        aws_vpc_security_group_rule
    where
        type = 'ingress'
        and cidr_ipv4 = '0.0.0.0/0'
        and (
        (
            ip_protocol = '-1'
            and from_port is null
        )
        or (
            from_port >= 3389
            and to_port <= 3389
        )
        )
    group by
        group_id
    )
    select
    arn as resource,
    case
        when ingress_ssh_rules.group_id is null then 'ok'
        else 'alarm'
    end as status,
    case
        when ingress_ssh_rules.group_id is null then sg.group_id || ' ingress restricted for RDP from 0.0.0.0/0.'
        else sg.group_id || ' contains ' || ingress_ssh_rules.num_ssh_rules || ' ingress rule(s) allowing RDP from 0.0.0.0/0.'
    end as reason,
    region,
    account_id
    from
    aws_vpc_security_group as sg
    left join ingress_ssh_rules on ingress_ssh_rules.group_id = sg.group_id;
    EOT
}   

#

control "vpc_security_group_restrict_ingress_tcp_udp_all" {
  title = "3.9 VPC security groups should restrict ingress TCP and UDP access from 0.0.0.0/0"
  severity = "high"
  sql = <<EOT
    with bad_rules as (
    select
        group_id,
        count(*) as num_bad_rules
    from
        aws_vpc_security_group_rule
    where
        type = 'ingress'
        and cidr_ipv4 = '0.0.0.0/0'
        and (
        ip_protocol in ('tcp', 'udp')
        or (
            ip_protocol = '-1'
            and from_port is null
        )
        )
    group by
        group_id
    )
    select
    arn as resource,
    case
        when bad_rules.group_id is null then 'ok'
        else 'alarm'
    end as status,
    case
        when bad_rules.group_id is null then sg.group_id || ' does not allow ingress to TCP or UDP ports from 0.0.0.0/0.'
        else sg.group_id || ' contains ' || bad_rules.num_bad_rules || ' rule(s) that allow ingress to TCP or UDP ports from 0.0.0.0/0.'
    end as reason,
    region,
    account_id
    from
    aws_vpc_security_group as sg
    left join bad_rules on bad_rules.group_id = sg.group_id;
    EOT
}  

#

control "autoscaling_ec2_launch_configuration_no_sensitive_data" {
  title = "3.10 EC2 auto scaling group launch configurations user data should not have any sensitive data"
  severity = "critical"
  sql = <<EOT
    select
    launch_configuration_arn as resource,
    case
        when user_data like any (array [ '%pass%', '%secret%', '%token%', '%key%' ])
        or user_data ~ '(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]' then 'alarm'
        else 'ok'
    end as status,
    case
        when user_data like any (array [ '%pass%', '%secret%', '%token%', '%key%' ])
        or user_data ~ '(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]' then title || ' has potential secret patterns in user data.'
        else title || ' does not contain secret patterns in user data.'
    end as reason,
    region,
    account_id
    from
    aws_ec2_launch_configuration;
    EOT
}  

#

control "cloudformation_stack_output_no_secrets" {
  title = "3.11 CloudFormation stacks outputs should not have any secrets"
  severity = "critical"
  sql = <<EOT
    with stack_output as (
    select
        id,
        jsonb_array_elements(outputs) -> 'OutputKey' as k,
        jsonb_array_elements(outputs) -> 'OutputValue' as v,
        region,
        account_id
    from
        aws_cloudformation_stack
    ),
    stack_with_secrets as (
    select
        distinct id
    from
        stack_output
    where
        lower(k :: text) like any (array [ '%pass%', '%secret%', '%token%', '%key%' ])
        or k :: text ~ '(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]'
        or lower(v :: text) like any (array [ '%pass%', '%secret%', '%token%', '%key%' ])
        or v :: text ~ '(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]'
    )
    select
    c.id as resource,
    case
        when c.outputs is null then 'ok'
        when s.id is null then 'ok'
        else 'alarm'
    end as status,
    case
        when c.outputs is null then title || ' has no outputs.'
        when s.id is null then title || ' no secrets found in outputs.'
        else title || ' has secrets in outputs.'
    end as reason,
    c.region,
    c.account_id
    from
    aws_cloudformation_stack as c
    left join stack_with_secrets as s on c.id = s.id;
    EOT
} 

#

control "ecs_task_definition_container_environment_no_secret" {
  title = "3.12 ECS task definition containers should not have secrets passed as environment variables"
  severity = "critical"
  sql = <<EOT
    with definitions_with_secret_environment_variable as (
    select
        distinct task_definition_arn as arn
    from
        aws_ecs_task_definition,
        jsonb_array_elements(container_definitions) as c,
        jsonb_array_elements(c -> 'Environment') as e,
        jsonb_array_elements(
        case
            jsonb_typeof(c -> 'Secrets')
            when 'array' then (c -> 'Secrets')
            else null
        end
        ) as s
    where
        e ->> 'Name' like any (
        array [ 'AWS_ACCESS_KEY_ID',
        'AWS_SECRET_ACCESS_KEY',
        'ECS_ENGINE_AUTH_DATA' ]
        )
        or s ->> 'Name' like any (
        array [ 'AWS_ACCESS_KEY_ID',
        'AWS_SECRET_ACCESS_KEY',
        'ECS_ENGINE_AUTH_DATA' ]
        )
    )
    select
    d.task_definition_arn as resource,
    case
        when e.arn is null then 'ok'
        else 'alarm'
    end as status,
    case
        when e.arn is null then d.title || ' container environment variables does not have secrets.'
        else d.title || ' container environment variables have secrets.'
    end as reason,
    region,
    account_id
    from
    aws_ecs_task_definition as d
    left join definitions_with_secret_environment_variable as e on d.task_definition_arn = e.arn;
    EOT
} 

#

control "ec2_instance_no_launch_wizard_security_group" {
  title = "3.13 EC2 instances should not be attached to 'launch wizard' security groups"
  severity = "low"
  sql = <<EOT
    with launch_wizard_sg_attached_instance as (
    select
        distinct arn as arn
    from
        aws_ec2_instance,
        jsonb_array_elements(security_groups) as sg
    where
        sg ->> 'GroupName' like 'launch-wizard%'
    )
    select
    i.arn as resource,
    case
        when sg.arn is null then 'ok'
        else 'alarm'
    end as status,
    case
        when sg.arn is null then i.title || ' not associated with launch-wizard security group.'
        else i.title || ' associated with launch-wizard security group.'
    end as reason,
    i.region,
    i.account_id
    from
    aws_ec2_instance as i
    left join launch_wizard_sg_attached_instance as sg on i.arn = sg.arn;
    EOT
} 

#


control "iam_policy_no_star_star" {
  title = "3.14 IAM policy should not have statements with admin access"
  severity = "medium"
  sql = <<EOT
    with bad_policies as (
    select
        arn,
        count(*) as num_bad_statements
    from
        aws_iam_policy,
        jsonb_array_elements(policy_std -> 'Statement') as s,
        jsonb_array_elements_text(s -> 'Resource') as resource,
        jsonb_array_elements_text(s -> 'Action') as action
    where
        not is_aws_managed
        and s ->> 'Effect' = 'Allow'
        and resource = '*'
        and (
        (
            action = '*'
            or action = '*:*'
        )
        )
    group by
        arn
    )
    select
    p.arn as resource,
    case
        when bad.arn is null then 'ok'
        else 'alarm'
    end status,
    p.name || ' contains ' || coalesce(bad.num_bad_statements, 0) || ' statements that allow action "*" on resource "*".' as reason,
    p.account_id
    from
    aws_iam_policy as p
    left join bad_policies as bad on p.arn = bad.arn
    where
    not p.is_aws_managed;
    EOT
} 

#

control "rds_db_instance_prohibit_public_access" {
  title = "3.15 RDS DB instances should prohibit public access, determined by the PubliclyAccessible configuration"
  severity = "high"
  sql = <<EOT
    select
    arn as resource,
    case
        when publicly_accessible then 'alarm'
        else 'ok'
    end status,
    case
        when publicly_accessible then title || ' publicly accessible.'
        else title || ' not publicly accessible.'
    end reason,
    region,
    account_id
    from
    aws_rds_db_instance;
    EOT
} 

#

control "s3_bucket_policy_restricts_cross_account_permission_changes" {
  title = "3.16 S3 permissions granted to other AWS accounts in bucket policies should be restricted"
  severity = "high"
  sql = <<EOT
    with cross_account_buckets as (
    select
        distinct arn
    from
        aws_s3_bucket,
        jsonb_array_elements(policy_std -> 'Statement') as s,
        jsonb_array_elements_text(s -> 'Principal' -> 'AWS') as p,
        string_to_array(p, ':') as pa,
        jsonb_array_elements_text(s -> 'Action') as a
    where
        s ->> 'Effect' = 'Allow'
        and (
        pa [ 5 ] != account_id
        or p = '*'
        )
        and a in (
        's3:deletebucketpolicy',
        's3:putbucketacl',
        's3:putbucketpolicy',
        's3:putencryptionconfiguration',
        's3:putobjectacl'
        )
    )
    select
    a.arn as resource,
    case
        when b.arn is null then 'ok'
        else 'alarm'
    end as status,
    case
        when b.arn is null then title || ' restricts cross-account bucket access.'
        else title || ' allows cross-account bucket access.'
    end as reason,
    a.region,
    a.account_id
    from
    aws_s3_bucket a
    left join cross_account_buckets b on a.arn = b.arn;
    EOT
} 

#

control "s3_bucket_restrict_public_read_access" {
  title = "3.17 S3 buckets should prohibit public read access"
  severity = "critical"
  sql = <<EOT
    with public_acl as (
    select
        distinct name
    from
        aws_s3_bucket,
        jsonb_array_elements(acl -> 'Grants') as grants
    where
        (
        grants -> 'Grantee' ->> 'URI' = 'http://acs.amazonaws.com/groups/global/AllUsers'
        or grants -> 'Grantee' ->> 'URI' = 'http://acs.amazonaws.com/groups/global/AuthenticatedUsers'
        )
        and (
        grants ->> 'Permission' = 'FULL_CONTROL'
        or grants ->> 'Permission' = 'READ_ACP'
        or grants ->> 'Permission' = 'READ'
        )
    ),
    read_access_policy as (
    select
        distinct name
    from
        aws_s3_bucket,
        jsonb_array_elements(policy_std -> 'Statement') as s,
        jsonb_array_elements_text(s -> 'Action') as action
    where
        s ->> 'Effect' = 'Allow'
        and (
        s -> 'Principal' -> 'AWS' = '["*"]'
        or s ->> 'Principal' = '*'
        )
        and (
        action = '*'
        or action = '*:*'
        or action = 's3:*'
        or action ilike 's3:get%'
        or action ilike 's3:list%'
        )
    )
    select
    b.arn as resource,
    case
        when (
        block_public_acls
        or a.name is null
        )
        and not bucket_policy_is_public then 'ok'
        when (
        block_public_acls
        or a.name is null
        )
        and (
        bucket_policy_is_public
        and block_public_policy
        ) then 'ok'
        when (
        block_public_acls
        or a.name is null
        )
        and (
        bucket_policy_is_public
        and p.name is null
        ) then 'ok'
        else 'alarm'
    end as status,
    case
        when (
        block_public_acls
        or a.name is null
        )
        and not bucket_policy_is_public then b.title || ' not publicly readable.'
        when (
        block_public_acls
        or a.name is null
        )
        and (
        bucket_policy_is_public
        and block_public_policy
        ) then b.title || ' not publicly readable.'
        when (
        block_public_acls
        or a.name is null
        )
        and (
        bucket_policy_is_public
        and p.name is null
        ) then b.title || ' not publicly readable.'
        else b.title || ' publicly readable.'
    end as reason,
    b.region,
    b.account_id
    from
    aws_s3_bucket as b
    left join public_acl as a on b.name = a.name
    left join read_access_policy as p on b.name = p.name;
    EOT
} 

#

control "s3_bucket_restrict_public_write_access" {
  title = "3.18 S3 buckets should prohibit public write access"
  severity = "critical"
  sql = <<EOT
    with public_acl as (
    select
        distinct name
    from
        aws_s3_bucket,
        jsonb_array_elements(acl -> 'Grants') as grants
    where
        (
        grants -> 'Grantee' ->> 'URI' = 'http://acs.amazonaws.com/groups/global/AllUsers'
        or grants -> 'Grantee' ->> 'URI' = 'http://acs.amazonaws.com/groups/global/AuthenticatedUsers'
        )
        and (
        grants ->> 'Permission' = 'FULL_CONTROL'
        or grants ->> 'Permission' = 'WRITE_ACP'
        or grants ->> 'Permission' = 'WRITE'
        )
    ),
    write_access_policy as (
    select
        distinct name
    from
        aws_s3_bucket,
        jsonb_array_elements(policy_std -> 'Statement') as s,
        jsonb_array_elements_text(s -> 'Action') as action
    where
        s ->> 'Effect' = 'Allow'
        and (
        s -> 'Principal' -> 'AWS' = '["*"]'
        or s ->> 'Principal' = '*'
        )
        and (
        action = '*'
        or action = '*:*'
        or action = 's3:*'
        or action ilike 's3:put%'
        or action ilike 's3:delete%'
        or action ilike 's3:create%'
        or action ilike 's3:update%'
        or action ilike 's3:replicate%'
        or action ilike 's3:restore%'
        )
    )
    select
    b.arn as resource,
    case
        when (
        block_public_acls
        or a.name is null
        )
        and not bucket_policy_is_public then 'ok'
        when (
        block_public_acls
        or a.name is null
        )
        and (
        bucket_policy_is_public
        and block_public_policy
        ) then 'ok'
        when bucket_policy_is_public
        and p.name is null then 'ok'
        else 'alarm'
    end status,
    case
        when (
        block_public_acls
        or a.name is null
        )
        and not bucket_policy_is_public then b.title || ' not publicly writable.'
        when (
        block_public_acls
        or a.name is null
        )
        and (
        bucket_policy_is_public
        and block_public_policy
        ) then b.title || ' not publicly writable.'
        when (
        block_public_acls
        or a.name is null
        )
        and (
        bucket_policy_is_public
        and p.name is null
        ) then b.title || ' not publicly writable.'
        else b.title || ' publicly writable.'
    end reason,
    b.region,
    b.account_id
    from
    aws_s3_bucket as b
    left join public_acl as a on b.name = a.name
    left join write_access_policy as p on b.name = p.name;
    EOT
} 

#

control "s3_public_access_block_bucket_account" {
  title = "3.19 S3 public access should be blocked at account level"
  severity = "high"
  sql = <<EOT
    select
    arn as resource,
    case
        when (
        bucket.block_public_acls
        or s3account.block_public_acls
        )
        and (
        bucket.block_public_policy
        or s3account.block_public_policy
        )
        and (
        bucket.ignore_public_acls
        or s3account.ignore_public_acls
        )
        and (
        bucket.restrict_public_buckets
        or s3account.restrict_public_buckets
        ) then 'ok'
        else 'alarm'
    end as status,
    case
        when (
        bucket.block_public_acls
        or s3account.block_public_acls
        )
        and (
        bucket.block_public_policy
        or s3account.block_public_policy
        )
        and (
        bucket.ignore_public_acls
        or s3account.ignore_public_acls
        )
        and (
        bucket.restrict_public_buckets
        or s3account.restrict_public_buckets
        ) then name || ' all public access blocks enabled.'
        else name || ' not enabled for: ' || concat_ws(
        ', ',
        case
            when not (
            bucket.block_public_acls
            or s3account.block_public_acls
            ) then 'block_public_acls'
        end,
        case
            when not (
            bucket.block_public_policy
            or s3account.block_public_policy
            ) then 'block_public_policy'
        end,
        case
            when not (
            bucket.ignore_public_acls
            or s3account.ignore_public_acls
            ) then 'ignore_public_acls'
        end,
        case
            when not (
            bucket.restrict_public_buckets
            or s3account.restrict_public_buckets
            ) then 'restrict_public_buckets'
        end
        ) || '.'
    end as reason,
    bucket.region,
    bucket.account_id
    from
    aws_s3_bucket as bucket,
    aws_s3_account_settings as s3account
    where
    s3account.account_id = bucket.account_id;
    EOT
} 

#

control "sqs_queue_policy_prohibit_public_access" {
  title = "3.20 SQS queue policies should prohibit public access"
  severity = "high"
  sql = <<EOT
    with wildcard_action_policies as (
    select
        queue_arn,
        count(*) as statements_num
    from
        aws_sqs_queue,
        jsonb_array_elements(policy_std -> 'Statement') as s
    where
        s ->> 'Effect' = 'Allow' -- aws:SourceOwner
        and s -> 'Condition' -> 'StringEquals' -> 'aws:sourceowner' is null
        and s -> 'Condition' -> 'StringEqualsIgnoreCase' -> 'aws:sourceowner' is null
        and (
        s -> 'Condition' -> 'StringLike' -> 'aws:sourceowner' is null
        or s -> 'Condition' -> 'StringLike' -> 'aws:sourceowner' ? '*'
        ) -- aws:SourceAccount
        and s -> 'Condition' -> 'StringEquals' -> 'aws:sourceaccount' is null
        and s -> 'Condition' -> 'StringEqualsIgnoreCase' -> 'aws:sourceaccount' is null
        and (
        s -> 'Condition' -> 'StringLike' -> 'aws:sourceaccount' is null
        or s -> 'Condition' -> 'StringLike' -> 'aws:sourceaccount' ? '*'
        ) -- aws:PrincipalOrgID
        and s -> 'Condition' -> 'StringEquals' -> 'aws:principalorgid' is null
        and s -> 'Condition' -> 'StringEqualsIgnoreCase' -> 'aws:principalorgid' is null
        and (
        s -> 'Condition' -> 'StringLike' -> 'aws:principalorgid' is null
        or s -> 'Condition' -> 'StringLike' -> 'aws:principalorgid' ? '*'
        ) -- aws:PrincipalAccount
        and s -> 'Condition' -> 'StringEquals' -> 'aws:principalaccount' is null
        and s -> 'Condition' -> 'StringEqualsIgnoreCase' -> 'aws:principalaccount' is null
        and (
        s -> 'Condition' -> 'StringLike' -> 'aws:principalaccount' is null
        or s -> 'Condition' -> 'StringLike' -> 'aws:principalaccount' ? '*'
        ) -- aws:PrincipalArn
        and s -> 'Condition' -> 'StringEquals' -> 'aws:principalarn' is null
        and s -> 'Condition' -> 'StringEqualsIgnoreCase' -> 'aws:principalarn' is null
        and (
        s -> 'Condition' -> 'StringLike' -> 'aws:principalarn' is null
        or s -> 'Condition' -> 'StringLike' -> 'aws:principalarn' ? '*'
        )
        and (
        s -> 'Condition' -> 'ArnEquals' -> 'aws:principalarn' is null
        or s -> 'Condition' -> 'ArnEquals' -> 'aws:principalarn' ? '*'
        )
        and (
        s -> 'Condition' -> 'ArnLike' -> 'aws:principalarn' is null
        or s -> 'Condition' -> 'ArnLike' -> 'aws:principalarn' ? '*'
        ) -- aws:SourceArn
        and s -> 'Condition' -> 'StringEquals' -> 'aws:sourcearn' is null
        and s -> 'Condition' -> 'StringEqualsIgnoreCase' -> 'aws:sourcearn' is null
        and (
        s -> 'Condition' -> 'StringLike' -> 'aws:sourcearn' is null
        or s -> 'Condition' -> 'StringLike' -> 'aws:sourcearn' ? '*'
        )
        and (
        s -> 'Condition' -> 'ArnEquals' -> 'aws:sourcearn' is null
        or s -> 'Condition' -> 'ArnEquals' -> 'aws:sourcearn' ? '*'
        )
        and (
        s -> 'Condition' -> 'ArnLike' -> 'aws:sourcearn' is null
        or s -> 'Condition' -> 'ArnLike' -> 'aws:sourcearn' ? '*'
        )
        and (
        s -> 'Principal' -> 'AWS' = '["*"]'
        or s ->> 'Principal' = '*'
        )
    group by
        queue_arn
    )
    select
    r.queue_arn as resource,
    case
        when r.policy is null then 'info'
        when p.queue_arn is null then 'ok'
        else 'alarm'
    end as status,
    case
        when r.policy is null then title || ' does not have a defined policy or has insufficient access to the policy.'
        when p.queue_arn is null then title || ' policy does not allow public access.'
        else title || ' policy contains ' || coalesce(p.statements_num, 0) || ' statement(s) that allow public access.'
    end as reason,
    region,
    account_id
    from
    aws_sqs_queue as r
    left join wildcard_action_policies as p on p.queue_arn = r.queue_arn
    EOT
} 

#

control "sns_topic_policy_prohibit_subscription_access" {
  title = "3.21 SNS topic policies should prohibit public access"
  severity = "high"
  sql = <<EOT
    with wildcard_action_policies as (
    select
        topic_arn,
        count(*) as statements_num
    from
        aws_sns_topic,
        jsonb_array_elements(policy_std -> 'Statement') as s,
        jsonb_array_elements_text(s -> 'Action') as a
    where
        s ->> 'Effect' = 'Allow'
        and (
        (s -> 'Principal' -> 'AWS') = '["*"]'
        or s ->> 'Principal' = '*'
        )
        and a in ('sns:subscribe', 'sns:receive')
        and s -> 'Condition' is null
    group by
        topic_arn
    )
    select
    t.topic_arn as resource,
    case
        when p.topic_arn is null then 'ok'
        else 'alarm'
    end as status,
    case
        when p.topic_arn is null then title || ' does not allow subscribe access without condition.'
        else title || ' contains ' || coalesce(p.statements_num, 0) || ' statements that allows subscribe access without condition.'
    end as reason,
    t.region,
    t.account_id
    from
    aws_sns_topic as t
    left join wildcard_action_policies as p on p.topic_arn = t.topic_arn;
    EOT
} 

#

control "ec2_ami_restrict_public_access" {
  title = "3.22 EC2 AMIs should restrict public access"
  severity = "high"
  sql = <<EOT
    select
    'arn:' || partition || ':ec2:' || region || ':' || account_id || ':image/' || image_id as resource,
    case
        when public then 'alarm'
        else 'ok'
    end status,
    case
        when public then title || ' publicly accessible.'
        else title || ' not publicly accessible.'
    end reason,
    region,
    account_id
    from
    aws_ec2_ami;
    EOT
} 

#

control "ec2_instance_not_publicly_accessible" {
  title = "3.23 EC2 instances should not have a public IP address"
  severity = "high"
  sql = <<EOT
    select
    arn as resource,
    case
        when public_ip_address is null then 'ok'
        else 'alarm'
    end status,
    case
        when public_ip_address is null then instance_id || ' not publicly accessible.'
        else instance_id || ' publicly accessible.'
    end reason,
    region,
    account_id
    from
    aws_ec2_instance;
    EOT
} 

#

control "ecr_repository_prohibit_public_access" {
  title = "3.24. ECR repositories should prohibit public access"
  severity = "medium"
  sql = <<EOT
    with open_access_ecr_repo as(
    select
        distinct arn
    from
        aws_ecr_repository,
        jsonb_array_elements(policy_std -> 'Statement') as s,
        jsonb_array_elements_text(s -> 'Principal' -> 'AWS') as p,
        string_to_array(p, ':') as pa,
        jsonb_array_elements_text(s -> 'Action') as a
    where
        s ->> 'Effect' = 'Allow'
        and (p = '*')
    )
    select
    r.arn as resource,
    case
        when o.arn is not null then 'alarm'
        else 'ok'
    end as status,
    case
        when o.arn is not null then r.title || ' allows public access.'
        else r.title || ' does not allow public access.'
    end as reason,
    r.region,
    r.account_id
    from
    aws_ecr_repository as r
    left join open_access_ecr_repo as o on r.arn = o.arn
    group by
    resource,
    status,
    reason,
    r.region,
    r.account_id,
    r.tags,
    r._ctx;
    EOT
} 


#

control "vpc_security_group_restricted_common_ports" {
  title = "3.25 Security groups should not allow unrestricted access to ports with high risk"
  severity = "high"
  sql = <<EOT
    with ingress_ssh_rules as (
    select
        group_id,
        count(*) as num_ssh_rules
    from
        aws_vpc_security_group_rule
    where
        type = 'ingress'
        and cidr_ipv4 = '0.0.0.0/0'
        and (
        (
            ip_protocol = '-1'
            and from_port is null
        )
        or (
            from_port >= 22
            and to_port <= 22
        )
        or (
            from_port >= 3389
            and to_port <= 3389
        )
        or (
            from_port >= 21
            and to_port <= 21
        )
        or (
            from_port >= 20
            and to_port <= 20
        )
        or (
            from_port >= 3306
            and to_port <= 3306
        )
        or (
            from_port >= 4333
            and to_port <= 4333
        )
        or (
            from_port >= 23
            and to_port <= 23
        )
        or (
            from_port >= 25
            and to_port <= 25
        )
        or (
            from_port >= 445
            and to_port <= 445
        )
        or (
            from_port >= 110
            and to_port <= 110
        )
        or (
            from_port >= 135
            and to_port <= 135
        )
        or (
            from_port >= 143
            and to_port <= 143
        )
        or (
            from_port >= 1433
            and to_port <= 3389
        )
        or (
            from_port >= 3389
            and to_port <= 1434
        )
        or (
            from_port >= 5432
            and to_port <= 5432
        )
        or (
            from_port >= 5500
            and to_port <= 5500
        )
        or (
            from_port >= 5601
            and to_port <= 5601
        )
        or (
            from_port >= 9200
            and to_port <= 9300
        )
        or (
            from_port >= 8080
            and to_port <= 8080
        )
        )
    group by
        group_id
    )
    select
    arn as resource,
    case
        when ingress_ssh_rules.group_id is null then 'ok'
        else 'alarm'
    end as status,
    case
        when ingress_ssh_rules.group_id is null then sg.group_id || ' ingress restricted for common ports from 0.0.0.0/0..'
        else sg.group_id || ' contains ' || ingress_ssh_rules.num_ssh_rules || ' ingress rule(s) allowing access for common ports from 0.0.0.0/0.'
    end as reason,
    sg.region,
    sg.account_id
    from
    aws_vpc_security_group as sg
    left join ingress_ssh_rules on ingress_ssh_rules.group_id = sg.group_id;
    EOT
} 

#

control "iam_role_trust_policy_prohibit_public_access" {
  title = "3.26 IAM role trust policies should prohibit public access"
  severity = "high"
  sql = <<EOT
    with wildcard_action_policies as (
    select
        arn,
        count(*) as statements_num
    from
        aws_iam_role,
        jsonb_array_elements(assume_role_policy_std -> 'Statement') as s
    where
        s ->> 'Effect' = 'Allow' -- aws:SourceOwner
        and s -> 'Condition' -> 'StringEquals' -> 'aws:sourceowner' is null
        and s -> 'Condition' -> 'StringEqualsIgnoreCase' -> 'aws:sourceowner' is null
        and (
        s -> 'Condition' -> 'StringLike' -> 'aws:sourceowner' is null
        or s -> 'Condition' -> 'StringLike' -> 'aws:sourceowner' ? '*'
        ) -- aws:SourceAccount
        and s -> 'Condition' -> 'StringEquals' -> 'aws:sourceaccount' is null
        and s -> 'Condition' -> 'StringEqualsIgnoreCase' -> 'aws:sourceaccount' is null
        and (
        s -> 'Condition' -> 'StringLike' -> 'aws:sourceaccount' is null
        or s -> 'Condition' -> 'StringLike' -> 'aws:sourceaccount' ? '*'
        ) -- aws:PrincipalOrgID
        and s -> 'Condition' -> 'StringEquals' -> 'aws:principalorgid' is null
        and s -> 'Condition' -> 'StringEqualsIgnoreCase' -> 'aws:principalorgid' is null
        and (
        s -> 'Condition' -> 'StringLike' -> 'aws:principalorgid' is null
        or s -> 'Condition' -> 'StringLike' -> 'aws:principalorgid' ? '*'
        ) -- aws:PrincipalAccount
        and s -> 'Condition' -> 'StringEquals' -> 'aws:principalaccount' is null
        and s -> 'Condition' -> 'StringEqualsIgnoreCase' -> 'aws:principalaccount' is null
        and (
        s -> 'Condition' -> 'StringLike' -> 'aws:principalaccount' is null
        or s -> 'Condition' -> 'StringLike' -> 'aws:principalaccount' ? '*'
        ) -- aws:PrincipalArn
        and s -> 'Condition' -> 'StringEquals' -> 'aws:principalarn' is null
        and s -> 'Condition' -> 'StringEqualsIgnoreCase' -> 'aws:principalarn' is null
        and (
        s -> 'Condition' -> 'StringLike' -> 'aws:principalarn' is null
        or s -> 'Condition' -> 'StringLike' -> 'aws:principalarn' ? '*'
        )
        and s -> 'Condition' -> 'ArnEquals' -> 'aws:principalarn' is null
        and (
        s -> 'Condition' -> 'ArnLike' -> 'aws:principalarn' is null
        or s -> 'Condition' -> 'ArnLike' -> 'aws:principalarn' ? '*'
        ) -- aws:SourceArn
        and s -> 'Condition' -> 'StringEquals' -> 'aws:sourcearn' is null
        and s -> 'Condition' -> 'StringEqualsIgnoreCase' -> 'aws:sourcearn' is null
        and (
        s -> 'Condition' -> 'StringLike' -> 'aws:sourcearn' is null
        or s -> 'Condition' -> 'StringLike' -> 'aws:sourcearn' ? '*'
        )
        and s -> 'Condition' -> 'ArnEquals' -> 'aws:sourcearn' is null
        and (
        s -> 'Condition' -> 'ArnLike' -> 'aws:sourcearn' is null
        or s -> 'Condition' -> 'ArnLike' -> 'aws:sourcearn' ? '*'
        )
        and (
        s -> 'Principal' -> 'AWS' = '["*"]'
        or s ->> 'Principal' = '*'
        )
    group by
        arn
    )
    select
    r.arn as resource,
    case
        when p.arn is null then 'ok'
        else 'alarm'
    end as status,
    case
        when p.arn is null then title || ' trust policy does not allow public access.'
        else title || ' trust policy contains ' || coalesce(p.statements_num, 0) || ' statement(s) that allow public access.'
    end as reason,
    r.region,
    r.account_id
    from
    aws_iam_role as r
    left join wildcard_action_policies as p on p.arn = r.arn;
    EOT
} 

#
control "cloudtrail_bucket_not_public" {
  title = "3.27 Ensure the S3 bucket CloudTrail logs to is not publicly accessible"
  severity = "critical"
  sql = <<EOT
    with public_bucket_data as (
    -- note the counts are not exactly CORRECT because of the jsonb_array_elements joins,
    -- but will be non-zero if any matches are found
    select
        t.s3_bucket_name as name,
        b.arn,
        t.region,
        t.account_id,
        t.tags,
        t._ctx,
        count(acl_grant) filter (
        where
            acl_grant -> 'Grantee' ->> 'URI' like '%acs.amazonaws.com/groups/global/AllUsers'
        ) as all_user_grants,
        count(acl_grant) filter (
        where
            acl_grant -> 'Grantee' ->> 'URI' like '%acs.amazonaws.com/groups/global/AuthenticatedUsers'
        ) as auth_user_grants,
        count(s) filter (
        where
            s ->> 'Effect' = 'Allow'
            and p = '*'
        ) as anon_statements
    from
        aws_cloudtrail_trail as t
        left join aws_s3_bucket as b on t.s3_bucket_name = b.name
        left join jsonb_array_elements(acl -> 'Grants') as acl_grant on true
        left join jsonb_array_elements(policy_std -> 'Statement') as s on true
        left join jsonb_array_elements_text(s -> 'Principal' -> 'AWS') as p on true
    group by
        t.s3_bucket_name,
        b.arn,
        t.region,
        t.account_id,
        t.tags,
        t._ctx
    )
    select
    case
        when arn is null then 'arn:aws:s3::' || name
        else arn
    end as resource,
    case
        when arn is null then 'skip'
        when all_user_grants > 0 then 'alarm'
        when auth_user_grants > 0 then 'alarm'
        when anon_statements > 0 then 'alarm'
        else 'ok'
    end as status,
    case
        when arn is null then name || ' not found in account ' || account_id || '.'
        when all_user_grants > 0 then name || ' grants access to AllUsers in ACL.'
        when auth_user_grants > 0 then name || ' grants access to AuthenticatedUsers in ACL.'
        when anon_statements > 0 then name || ' grants access to AWS:*" in bucket policy.'
        else name || ' does not grant anonymous access in ACL or bucket policy.'
    end as reason,
    region,
    account_id
    from
    public_bucket_data;
    EOT
} 

#


control "efs_file_system_restrict_public_access" {
  title = "3.28 EFS file systems should restrict public access"
  severity = "high"
  sql = <<EOT
    with wildcard_action_policies as (
    select
        arn,
        count(*) as statements_num
    from
        aws_efs_file_system,
        jsonb_array_elements(policy_std -> 'Statement') as s
    where
        s ->> 'Effect' = 'Allow'
        and (
        (s -> 'Principal' -> 'AWS') = '["*"]'
        or s ->> 'Principal' = '*'
        )
    group by
        arn
    )
    select
    f.arn as resource,
    case
        when p.arn is null then 'ok'
        else 'alarm'
    end as status,
    case
        when p.arn is null then title || ' does not allow public access.'
        else title || ' contains ' || coalesce(p.statements_num, 0) || ' statements that allows public access.'
    end as reason,
    f.region,
    f.account_id
    from
    aws_efs_file_system as f
    left join wildcard_action_policies as p on p.arn = f.arn;
    EOT
} 

#

control "elb_application_classic_network_lb_prohibit_public_access" {
  title = "3.29 ELB load balancers should prohibit public access"
  severity = "high"
  sql = <<EOT
    with all_lb_details as (
    select
        arn,
        scheme,
        title,
        region,
        account_id,
        tags,
        _ctx
    from
        aws_ec2_application_load_balancer
    union
    select
        arn,
        scheme,
        title,
        region,
        account_id,
        tags,
        _ctx
    from
        aws_ec2_network_load_balancer
    union
    select
        arn,
        scheme,
        title,
        region,
        account_id,
        tags,
        _ctx
    from
        aws_ec2_classic_load_balancer
    )
    select
    arn as resource,
    case
        when scheme = 'internet-facing' then 'alarm'
        else 'ok'
    end as status,
    case
        when scheme = 'internet-facing' then title || ' publicly accessible.'
        else title || ' not publicly accessible.'
    end as reason,
    region,
    account_id
    from
    all_lb_details;
    EOT
} 

#

control "ssm_document_prohibit_public_access" {
  title = "3.30 SSM documents should not be public"
  severity = "high"
  sql = <<EOT
    select
    'arn:' || partition || ':ssm:' || region || ':' || account_id || ':document/' || name as resource,
    case
        when account_ids :: jsonb ? 'all' then 'alarm'
        else 'ok'
    end as status,
    case
        when account_ids :: jsonb ? 'all' then title || ' publicly accesible.'
        else title || ' not publicly accesible.'
    end as reason,
    region,
    account_id
    from
    aws_ssm_document
    where
    owner_type = 'Self';
    EOT
} 

#

control "ebs_attached_volume_encryption_enabled" {
  title = "3.31 Attached EBS volumes should have encryption enabled"
  severity = "medium"
  sql = <<EOT
    select
    arn as resource,
    case
        when state != 'in-use' then 'skip'
        when encrypted then 'ok'
        else 'alarm'
    end as status,
    case
        when state != 'in-use' then volume_id || ' not attached.'
        when encrypted then volume_id || ' encrypted.'
        else volume_id || ' not encrypted.'
    end as reason,
    region,
    account_id
    from
    aws_ebs_volume;
    EOT
} 

#

control "kms_cmk_policy_prohibit_public_access" {
  title = "3.32 KMS CMK policies should prohibit public access"
  severity = "high"
  sql = <<EOT
    with wildcard_action_policies as (
    select
        arn,
        count(*) as statements_num
    from
        aws_kms_key,
        jsonb_array_elements(policy_std -> 'Statement') as s
    where
        s ->> 'Effect' = 'Allow'
        and (
        (s -> 'Principal' -> 'AWS') = '["*"]'
        or s ->> 'Principal' = '*'
        )
        and key_manager = 'CUSTOMER'
    group by
        arn
    )
    select
    k.arn as resource,
    case
        when p.arn is null then 'ok'
        else 'alarm'
    end status,
    case
        when p.arn is null then title || ' does not allow public access.'
        else title || ' contains ' || coalesce(p.statements_num, 0) || ' statements that allow public access.'
    end as reason,
    k.region,
    k.account_id
    from
    aws_kms_key as k
    left join wildcard_action_policies as p on p.arn = k.arn
    where
    key_manager = 'CUSTOMER';
    EOT
} 

#

control "lambda_function_restrict_public_access" {
  title = "3.33 Lambda functions should restrict public access"
  severity = "low"
  sql = <<EOT
    with wildcard_action_policies as (
    select
        arn,
        count(*) as statements_num
    from
        aws_lambda_function,
        jsonb_array_elements(policy_std -> 'Statement') as s
    where
        s ->> 'Effect' = 'Allow'
        and (
        (s -> 'Principal' -> 'AWS') = '["*"]'
        or s ->> 'Principal' = '*'
        )
    group by
        arn
    )
    select
    f.arn as resource,
    case
        when p.arn is null then 'ok'
        else 'alarm'
    end as status,
    case
        when p.arn is null then title || ' does not allow public access.'
        else title || ' contains ' || coalesce(p.statements_num, 0) || ' statements that allows public access.'
    end as reason,
    f.region,
    f.account_id
    from
    aws_lambda_function as f
    left join wildcard_action_policies as p on p.arn = f.arn;
    EOT
} 

#

control "eks_cluster_endpoint_public_access_restricted" {
  title = "3.34 EKS clusters endpoint should restrict public access"
  severity = "high"
  sql = <<EOT
    select
    arn as resource,
    case
        when resources_vpc_config ->> 'EndpointPrivateAccess' = 'true'
        and resources_vpc_config ->> 'EndpointPublicAccess' = 'false' then 'ok'
        when resources_vpc_config ->> 'EndpointPublicAccess' = 'true'
        and resources_vpc_config -> 'PublicAccessCidrs' @> '["0.0.0.0/0"]' then 'alarm'
        else 'ok'
    end as status,
    case
        when resources_vpc_config ->> 'EndpointPrivateAccess' = 'true'
        and resources_vpc_config ->> 'EndpointPublicAccess' = 'false' then title || ' endpoint access is private.'
        when resources_vpc_config ->> 'EndpointPublicAccess' = 'true'
        and resources_vpc_config -> 'PublicAccessCidrs' @> '["0.0.0.0/0"]' then title || ' endpoint access is public.'
        else title || ' endpoint public access is restricted.'
    end as reason,
    region,
    account_id
    from
    aws_eks_cluster;
    EOT
} 

#

control "eks_cluster_secrets_encrypted" {
  title = "3.35 EKS clusters should be configured to have kubernetes secrets encrypted using KMS"
  severity = "high"
  sql = <<EOT
    with eks_secrets_encrypted as (
    select
        distinct arn as arn
    from
        aws_eks_cluster,
        jsonb_array_elements(encryption_config) as e
    where
        e -> 'Resources' @> '["secrets"]'
    )
    select
    a.arn as resource,
    case
        when encryption_config is null then 'alarm'
        when b.arn is not null then 'ok'
        else 'alarm'
    end as status,
    case
        when encryption_config is null then a.title || ' encryption not enabled.'
        when b.arn is not null then a.title || ' encrypted with EKS secrets.'
        else a.title || ' not encrypted with EKS secrets.'
    end as reason,
    region,
    account_id
    from
    aws_eks_cluster as a
    left join eks_secrets_encrypted as b on a.arn = b.arn;
    EOT
} 

#

control "eks_cluster_control_plane_audit_logging_enabled" {
  title = "3.36 EKS clusters should have control plane audit logging enabled"
  severity = "high"
  sql = <<EOT
    with control_panel_audit_logging as (
    select
        distinct arn,
        log -> 'Types' as log_type
    from
        aws_eks_cluster,
        jsonb_array_elements(logging -> 'ClusterLogging') as log
    where
        log ->> 'Enabled' = 'true'
        and (log -> 'Types') @> '["api", "audit", "authenticator", "controllerManager", "scheduler"]'
    )
    select
    c.arn as resource,
    case
        when l.arn is not null then 'ok'
        else 'alarm'
    end as status,
    case
        when l.arn is not null then c.title || ' control plane audit logging enabled for all log types.'
        else case
        when logging -> 'ClusterLogging' @> '[{"Enabled": true}]' then c.title || ' control plane audit logging not enabled for all log types.'
        else c.title || ' control plane audit logging not enabled.'
        end
    end as reason,
    c.region,
    c.account_id
    from
    aws_eks_cluster as c
    left join control_panel_audit_logging as l on l.arn = c.arn;
    EOT
} 

#

control "cloudfront_distribution_no_non_existent_s3_origin" {
  title = "3.37 CloudFront distributions should not point to non-existent S3 origins"
  severity = "high"
  sql = <<EOT
    with distribution_with_non_existent_bucket as (
    select
        distinct d.arn as arn,
        to_jsonb(
        string_to_array(
            (string_agg(split_part(o ->> 'Id', '.s3', 1), ',')),
            ','
        )
        ) as bucket_name_list
    from
        aws_cloudfront_distribution as d,
        jsonb_array_elements(d.origins) as o
        left join aws_s3_bucket as b on b.name = split_part(o ->> 'Id', '.s3', 1)
    where
        b.name is null
        and o ->> 'DomainName' like '%.s3.%'
    group by
        d.arn
    )
    select
    distinct b.arn as resource,
    case
        when b.arn is null then 'ok'
        else 'alarm'
    end as status,
    case
        when b.arn is null then title || ' does not point to any non-existent S3 origins.'
        when jsonb_array_length(b.bucket_name_list) > 0 then title || case
        when jsonb_array_length(b.bucket_name_list) > 2 then concat(
            ' point to non-existent S3 origins ',
            b.bucket_name_list #> > '{0}',
            ', ',
            b.bucket_name_list #> > '{1}',
            ' and ' || (jsonb_array_length(b.bucket_name_list) - 2) :: text || ' more.'
        )
        when jsonb_array_length(b.bucket_name_list) = 2 then concat(
            ' point to non-existent S3 origins ',
            b.bucket_name_list #> > '{0}',
            ' and ',
            b.bucket_name_list #> > '{1}',
            '.'
        )
        else concat(
            ' point to non-existent S3 origin ',
            b.bucket_name_list #> > '{0}',
            '.'
        )
        end
    end as reason,
    region,
    account_id
    from
    aws_cloudfront_distribution as d
    left join distribution_with_non_existent_bucket as b on b.arn = d.arn;
    EOT
} 

#

control "ecr_repository_image_scan_on_push_enabled" {
  title = "3.38 ECR private repositories should have image scanning configured"
  severity = "high"
  sql = <<EOT
    select
    arn as resource,
    case
        when image_scanning_configuration ->> 'ScanOnPush' = 'true' then 'ok'
        else 'alarm'
    end as status,
    case
        when image_scanning_configuration ->> 'ScanOnPush' = 'true' then title || ' scan on push enabled.'
        else title || ' scan on push disabled.'
    end as reason,
    region,
    account_id
    from
    aws_ecr_repository;
    EOT
} 

#

control "ecs_task_definition_container_readonly_root_filesystem" {
  title = "3.39 ECS containers should be limited to read-only access to root filesystems"
  severity = "high"
  sql = <<EOT
    with privileged_container_definition as (
    select
        distinct task_definition_arn as arn
    from
        aws_ecs_task_definition,
        jsonb_array_elements(container_definitions) as c
    where
        c ->> 'ReadonlyRootFilesystem' = 'true'
    )
    select
    d.task_definition_arn as resource,
    case
        when c.arn is not null then 'ok'
        else 'alarm'
    end as status,
    case
        when c.arn is not null then d.title || ' containers limited to read-only access to root filesystems.'
        else d.title || ' containers not limited to read-only access to root filesystems.'
    end as reason,
    region,
    account_id
    from
    aws_ecs_task_definition as d
    left join privileged_container_definition as c on d.task_definition_arn = c.arn;
    EOT
} 

#

control "eks_cluster_with_latest_kubernetes_version" {
  title = "3.40 EKS clusters should run on a supported Kubernetes version"
  severity = "high"
  sql = <<EOT
    select
    arn as resource,
    case
        -- eks:oldestVersionSupported (Current oldest supported version is 1.19)
        when (version) :: decimal >= 1.19 then 'ok'
        else 'alarm'
    end as status,
    case
        when (version) :: decimal >= 1.19 then title || ' runs on a supported kubernetes version.'
        else title || ' does not run on a supported kubernetes version.'
    end as reason,
    region,
    account_id
    from
    aws_eks_cluster;
    EOT
} 

#

control "iam_policy_custom_attached_no_star_star" {
  title = "3.41 IAM policies should not allow full '*' administrative privileges"
  severity = "high"
  sql = <<EOT
    with star_access_policies as (
    select
        arn,
        count(*) as num_bad_statements
    from
        aws_iam_policy,
        jsonb_array_elements(policy_std -> 'Statement') as s,
        jsonb_array_elements_text(s -> 'Resource') as resource,
        jsonb_array_elements_text(s -> 'Action') as action
    where
        not is_aws_managed
        and s ->> 'Effect' = 'Allow'
        and resource = '*'
        and (
        (
            action = '*'
            or action = '*:*'
        )
        )
        and is_attached
    group by
        arn
    )
    select
    p.arn as resource,
    case
        when s.arn is null then 'ok'
        else 'alarm'
    end status,
    p.name || ' contains ' || coalesce(s.num_bad_statements, 0) || ' statements that allow action "*" on resource "*".' as reason,
    p.account_id
    from
    aws_iam_policy as p
    left join star_access_policies as s on p.arn = s.arn
    where
    not p.is_aws_managed;
    EOT
}

# 

control "iam_root_user_no_access_keys" {
  title = "3.42 IAM root user access key should not exist"
  severity = "critical"
  sql = <<EOT
    select
    'arn:' || partition || ':::' || account_id as resource,
    case
        when account_access_keys_present > 0 then 'alarm'
        else 'ok'
    end status,
    case
        when account_access_keys_present > 0 then 'Root user access keys exist.'
        else 'No root user access keys exist.'
    end reason,
    account_id
    from
    aws_iam_account_summary;
    EOT
}

#

control "kms_key_not_pending_deletion" {
  title = "3.43 AWS KMS keys should not be unintentionally deleted "
  severity = "critical"
  sql = <<EOT
    select
    arn as resource,
    case
        when key_state = 'PendingDeletion' then 'alarm'
        else 'ok'
    end as status,
    case
        when key_state = 'PendingDeletion' then title || ' scheduled for deletion and will be deleted in ' || extract(
        day
        from
            deletion_date - current_timestamp
        ) || ' day(s).'
        else title || ' not scheduled for deletion.'
    end as reason,
    region,
    account_id
    from
    aws_kms_key
    where
    key_manager = 'CUSTOMER';
    EOT
}


#

control "opensearch_domain_in_vpc" {
  title = "3.44 OpenSearch domains should be in a VPC"
  severity = "critical"
  sql = <<EOT
    with public_subnets as (
    select
        distinct a -> 'SubnetId' as SubnetId
    from
        aws_vpc_route_table as t,
        jsonb_array_elements(associations) as a,
        jsonb_array_elements(routes) as r
    where
        r ->> 'DestinationCidrBlock' = '0.0.0.0/0'
        and r ->> 'GatewayId' like 'igw-%'
    ),
    opensearch_domain_with_public_subnet as (
    select
        arn
    from
        aws_opensearch_domain,
        jsonb_array_elements(vpc_options -> 'SubnetIds') as s
    where
        s in (
        select
            SubnetId
        from
            public_subnets
        )
    )
    select
    d.arn as resource,
    case
        when d.vpc_options ->> 'VPCId' is null then 'alarm'
        when d.vpc_options ->> 'VPCId' is not null
        and p.arn is not null then 'alarm'
        else 'ok'
    end status,
    case
        when vpc_options ->> 'VPCId' is null then title || ' not in VPC.'
        when d.vpc_options ->> 'VPCId' is not null
        and p.arn is not null then title || ' attached to public subnet.'
        else title || ' in VPC ' || (vpc_options ->> 'VPCId') || '.'
    end reason,
    d.region,
    d.account_id
    from
    aws_opensearch_domain as d
    left join opensearch_domain_with_public_subnet as p on d.arn = p.arn;
    EOT
}

#

control "opensearch_domain_fine_grained_access_enabled" {
  title = "3.45 OpenSearch domains should have fine-grained access control enabled"
  severity = "high"
  sql = <<EOT
    select
    arn as resource,
    case
        when advanced_security_options is null
        or not (advanced_security_options -> 'Enabled') :: boolean then 'alarm'
        else 'ok'
    end as status,
    case
        when advanced_security_options is null
        or not (advanced_security_options -> 'Enabled') :: boolean then title || ' has fine-grained access control disabled.'
        else title || ' has fine-grained access control enabled.'
    end as reason,
    region,
    account_id
    from
    aws_opensearch_domain;
    EOT
}



#

control "rds_db_snapshot_prohibit_public_access" {
  title = "3.46 RDS snapshots should be private"
  severity = "critical"
  sql = <<EOT
    (
    select
        arn as resource,
        case
        when cluster_snapshot -> 'AttributeValues' = '["all"]' then 'alarm'
        else 'ok'
        end status,
        case
        when cluster_snapshot -> 'AttributeValues' = '["all"]' then title || ' publicly restorable.'
        else title || ' not publicly restorable.'
        end reason,
        region,
        account_id
    from
        aws_rds_db_cluster_snapshot,
        jsonb_array_elements(db_cluster_snapshot_attributes) as cluster_snapshot
    )
    union
    (
    select
        arn as resource,
        case
        when database_snapshot -> 'AttributeValues' = '["all"]' then 'alarm'
        else 'ok'
        end status,
        case
        when database_snapshot -> 'AttributeValues' = '["all"]' then title || ' publicly restorable.'
        else title || ' not publicly restorable.'
        end reason,
        region,
        account_id
    from
        aws_rds_db_snapshot,
        jsonb_array_elements(db_snapshot_attributes) as database_snapshot
    );
    EOT
}

#

control "ssm_managed_instance_compliance_patch_compliant" {
  title = "3.47 All EC2 instances managed by Systems Manager should be compliant with patching requirements"
  severity = "high"
  sql = <<EOT
    select
    id as resource,
    case
        when c.status = '' then 'skip'
        when c.status = 'COMPLIANT' then 'ok'
        else 'alarm'
    end as status,
    case
        when c.status = '' then 'Patch is not applicable for instance ' || i.title || '.'
        when c.status = 'COMPLIANT' then c.resource_id || ' patch ' || c.title || ' is compliant.'
        else c.resource_id || ' patch ' || c.title || ' is non-compliant.'
    end as reason,
    c.region,
    c.account_id
    from
    aws_ssm_managed_instance as i,
    aws_ssm_managed_instance_compliance as c
    where
    c.resource_id = i.instance_id
    and c.compliance_type = 'Patch';
    EOT
}

#

control "autoscaling_launch_config_requires_imdsv2" {
  title = "3.48 Auto Scaling group should configure EC2 instances to require Instance Metadata Service Version 2 (IMDSv2)"
  severity = "high"
  sql = <<EOT
    select
    launch_configuration_arn as resource,
    case
        when metadata_options_http_tokens = 'required' then 'ok'
        else 'alarm'
    end as status,
    case
        when metadata_options_http_tokens = 'required' then title || ' configured to use Instance Metadata Service Version 2 (IMDSv2).'
        else title || ' not configured to use Instance Metadata Service Version 2 (IMDSv2).'
    end as reason,
    region,
    account_id
    from
    aws_ec2_launch_configuration;
    EOT
}