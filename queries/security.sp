query "vpc_security_group_allows_ingress_to_cassandra_ports" {
  title = "3.1 VPC security groups should restrict ingress from 0.0.0.0/0 or ::/0 to cassandra ports 7199 or 9160 or 8888"
  sql = <<EOT
    WITH ingress_cassandra_rules AS (
        SELECT
            group_id,
            COUNT(*) AS num_cassandra_rules
        FROM
            aws_vpc_security_group_rule
        WHERE
            type = 'ingress'
            AND cidr_ipv4 = '0.0.0.0/0'
            AND (
                (
                    ip_protocol = '-1'
                    AND from_port IS NULL
                )
                OR (
                    from_port >= 7199
                    AND to_port <= 7199
                )
                OR (
                    from_port >= 9160
                    AND to_port <= 9160
                )
                OR (
                    from_port >= 8888
                    AND to_port <= 8888
                )
            )
        GROUP BY
            group_id
    )
    SELECT
        arn AS resource,
        CASE
            WHEN ingress_cassandra_rules.group_id IS NULL THEN 'ok'
            ELSE 'alarm'
        END AS status,
        CASE
            WHEN ingress_cassandra_rules.group_id IS NULL THEN sg.group_id || ' ingress restricted for cassandra ports from 0.0.0.0/0.'
            ELSE sg.group_id || ' contains ' || ingress_cassandra_rules.num_cassandra_rules || ' ingress rule(s) allowing access for cassandra ports from 0.0.0.0/0.'
        END AS reason,
        sg.region,
        sg.account_id
    FROM
        aws_vpc_security_group AS sg
    LEFT JOIN
        ingress_cassandra_rules ON ingress_cassandra_rules.group_id = sg.group_id
    WHERE
        CASE
            WHEN ingress_cassandra_rules.group_id IS NULL THEN 'ok'
            ELSE 'alarm'
        END = 'alarm';

    EOT
}    

query "vpc_security_group_allows_ingress_to_memcached_port" {
  title = "3.2 VPC security groups should restrict ingress from 0.0.0.0/0 or ::/0 to memcached port 11211"
  sql = <<EOT
    WITH ingress_memcached_rules AS (
        SELECT
            group_id,
            COUNT(*) AS num_memcached_rules
        FROM
            aws_vpc_security_group_rule
        WHERE
            type = 'ingress'
            AND cidr_ipv4 = '0.0.0.0/0'
            AND (
                (
                    ip_protocol = '-1'
                    AND from_port IS NULL
                )
                OR (
                    from_port >= 11211
                    AND to_port <= 11211
                )
            )
        GROUP BY
            group_id
    )
    SELECT
        sg.group_id AS resource,
        CASE
            WHEN ingress_memcached_rules.group_id IS NULL THEN 'ok'
            ELSE 'alarm'
        END AS status,
        CASE
            WHEN ingress_memcached_rules.group_id IS NULL THEN sg.group_id || ' ingress restricted for memcached port from 0.0.0.0/0.'
            ELSE sg.group_id || ' contains ' || ingress_memcached_rules.num_memcached_rules || ' ingress rule(s) allowing access for memcached port from 0.0.0.0/0.'
        END AS reason,
        sg.region,
        sg.account_id
    FROM
        aws_vpc_security_group AS sg
    LEFT JOIN
        ingress_memcached_rules ON ingress_memcached_rules.group_id = sg.group_id
    WHERE
        CASE
            WHEN ingress_memcached_rules.group_id IS NULL THEN 'ok'
            ELSE 'alarm'
        END = 'alarm';

    EOT
}   

query "vpc_security_group_allows_ingress_to_mongodb_ports" {
  title = "3.3 VPC security groups should restrict ingress from 0.0.0.0/0 or ::/0 to mongoDB ports 27017 and 27018"
  sql = <<EOT
    WITH ingress_mongodb_rules AS (
        SELECT
            group_id,
            COUNT(*) AS num_mongodb_rules
        FROM
            aws_vpc_security_group_rule
        WHERE
            type = 'ingress'
            AND cidr_ipv4 = '0.0.0.0/0'
            AND (
                (
                    ip_protocol = '-1'
                    AND from_port IS NULL
                )
                OR (
                    from_port >= 27017
                    AND to_port <= 27017
                )
                OR (
                    from_port >= 27018
                    AND to_port <= 27018
                )
            )
        GROUP BY
            group_id
    )
    SELECT
        sg.group_id AS resource,
        CASE
            WHEN ingress_mongodb_rules.group_id IS NULL THEN 'ok'
            ELSE 'alarm'
        END AS status,
        CASE
            WHEN ingress_mongodb_rules.group_id IS NULL THEN sg.group_id || ' ingress restricted for MongoDB ports from 0.0.0.0/0.'
            ELSE sg.group_id || ' contains ' || ingress_mongodb_rules.num_mongodb_rules || ' ingress rule(s) allowing access for MongoDB ports from 0.0.0.0/0.'
        END AS reason,
        sg.region,
        sg.account_id
    FROM
        aws_vpc_security_group AS sg
    LEFT JOIN
        ingress_mongodb_rules ON ingress_mongodb_rules.group_id = sg.group_id
    WHERE
        CASE
            WHEN ingress_mongodb_rules.group_id IS NULL THEN 'ok'
            ELSE 'alarm'
        END = 'alarm';

    EOT
}   

#

query "vpc_security_group_allows_ingress_to_oracle_ports" {
  title = "3.4 VPC security groups should restrict ingress from 0.0.0.0/0 or ::/0 to oracle ports 1521 or 2483"
  sql = <<EOT
    WITH ingress_oracle_rules AS (
        SELECT
            group_id,
            COUNT(*) AS num_oracle_rules
        FROM
            aws_vpc_security_group_rule
        WHERE
            type = 'ingress'
            AND cidr_ipv4 = '0.0.0.0/0'
            AND (
                (
                    ip_protocol = '-1'
                    AND from_port IS NULL
                )
                OR (
                    from_port >= 1521
                    AND to_port <= 1521
                )
                OR (
                    from_port >= 2483
                    AND to_port <= 2483
                )
            )
        GROUP BY
            group_id
    )
    SELECT
        sg.group_id AS resource,
        CASE
            WHEN ingress_oracle_rules.group_id IS NULL THEN 'ok'
            ELSE 'alarm'
        END AS status,
        CASE
            WHEN ingress_oracle_rules.group_id IS NULL THEN sg.group_id || ' ingress restricted for Oracle ports from 0.0.0.0/0.'
            ELSE sg.group_id || ' contains ' || ingress_oracle_rules.num_oracle_rules || ' ingress rule(s) allowing access for Oracle ports from 0.0.0.0/0.'
        END AS reason,
        sg.region,
        sg.account_id
    FROM
        aws_vpc_security_group AS sg
    LEFT JOIN
        ingress_oracle_rules ON ingress_oracle_rules.group_id = sg.group_id
    WHERE
        CASE
            WHEN ingress_oracle_rules.group_id IS NULL THEN 'ok'
            ELSE 'alarm'
        END = 'alarm';

    EOT
}   

#

query "vpc_security_group_restrict_ingress_kafka_port" {
  title = "3.5 VPC security groups should restrict ingress Kafka port access from 0.0.0.0/0"
  sql = <<EOT
    WITH ingress_kafka_port AS (
        SELECT
            group_id,
            COUNT(*) AS num_kafka_rules
        FROM
            aws_vpc_security_group_rule
        WHERE
            type = 'ingress'
            AND (
                cidr_ipv4 = '0.0.0.0/0'
                OR cidr_ipv6 = '::/0'
            )
            AND (
                (
                    ip_protocol = '-1'
                    AND from_port IS NULL
                )
                OR (
                    from_port >= 9092
                    AND to_port <= 9092
                )
            )
        GROUP BY
            group_id
    )
    SELECT
        sg.group_id AS resource,
        CASE
            WHEN ingress_kafka_port.group_id IS NULL THEN 'ok'
            ELSE 'alarm'
        END AS status,
        CASE
            WHEN ingress_kafka_port.group_id IS NULL THEN sg.group_id || ' ingress restricted for Kafka port from 0.0.0.0/0.'
            ELSE sg.group_id || ' contains ' || ingress_kafka_port.num_kafka_rules || ' ingress rule(s) allowing Kafka port from 0.0.0.0/0.'
        END AS reason,
        sg.region,
        sg.account_id
    FROM
        aws_vpc_security_group AS sg
    LEFT JOIN
        ingress_kafka_port ON ingress_kafka_port.group_id = sg.group_id
    WHERE
        CASE
            WHEN ingress_kafka_port.group_id IS NULL THEN 'ok'
            ELSE 'alarm'
        END = 'alarm';

    EOT
}   

#

query "vpc_security_group_restrict_ingress_redis_port" {
  title = "3.6 VPC security groups should restrict ingress redis access from 0.0.0.0/0"
  sql = <<EOT
    WITH ingress_redis_port AS (
        SELECT
            group_id,
            COUNT(*) AS num_redis_rules
        FROM
            aws_vpc_security_group_rule
        WHERE
            type = 'ingress'
            AND (
                cidr_ipv4 = '0.0.0.0/0'
                OR cidr_ipv6 = '::/0'
            )
            AND (
                (
                    ip_protocol = '-1'
                    AND from_port IS NULL
                )
                OR (
                    from_port >= 6379
                    AND to_port <= 6379
                )
            )
        GROUP BY
            group_id
    )
    SELECT
        sg.group_id AS resource,
        CASE
            WHEN ingress_redis_port.group_id IS NULL THEN 'ok'
            ELSE 'alarm'
        END AS status,
        CASE
            WHEN ingress_redis_port.group_id IS NULL THEN sg.group_id || ' restricted ingress from 0.0.0.0/0 or ::/0 to Redis port 6379.'
            ELSE sg.group_id || ' contains ' || ingress_redis_port.num_redis_rules || ' ingress rule(s) from 0.0.0.0/0 or ::/0 to Redis port 6379.'
        END AS reason,
        region,
        account_id
    FROM
        aws_vpc_security_group AS sg
    LEFT JOIN
        ingress_redis_port ON ingress_redis_port.group_id = sg.group_id
    WHERE
        CASE
            WHEN ingress_redis_port.group_id IS NULL THEN 'ok'
            ELSE 'alarm'
        END = 'alarm';

    EOT
}   

#

query "vpc_security_group_restrict_ingress_ssh_all" {
  title = "3.7 VPC security groups should restrict ingress SSH access from 0.0.0.0/0"
  sql = <<EOT
    WITH ingress_ssh_rules AS (
        SELECT
            group_id,
            COUNT(*) AS num_ssh_rules
        FROM
            aws_vpc_security_group_rule
        WHERE
            type = 'ingress'
            AND cidr_ipv4 = '0.0.0.0/0'
            AND (
                (
                    ip_protocol = '-1'
                    AND from_port IS NULL
                )
                OR (
                    from_port >= 22
                    AND to_port <= 22
                )
            )
        GROUP BY
            group_id
    )
    SELECT
        sg.group_id AS resource,
        CASE
            WHEN ingress_ssh_rules.group_id IS NULL THEN 'ok'
            ELSE 'alarm'
        END AS status,
        CASE
            WHEN ingress_ssh_rules.group_id IS NULL THEN sg.group_id || ' ingress restricted for SSH from 0.0.0.0/0.'
            ELSE sg.group_id || ' contains ' || ingress_ssh_rules.num_ssh_rules || ' ingress rule(s) allowing SSH from 0.0.0.0/0.'
        END AS reason,
        region,
        account_id
    FROM
        aws_vpc_security_group AS sg
    LEFT JOIN
        ingress_ssh_rules ON ingress_ssh_rules.group_id = sg.group_id
    WHERE
        CASE
            WHEN ingress_ssh_rules.group_id IS NULL THEN 'ok'
            ELSE 'alarm'
        END = 'alarm';

    EOT
}   

#

query "vpc_security_group_restrict_ingress_rdp_all" {
  title = "3.8 VPC security groups should restrict ingress RDP access from 0.0.0.0/0"
  sql = <<EOT
    WITH ingress_rdp_rules AS (
        SELECT
            group_id,
            COUNT(*) AS num_rdp_rules
        FROM
            aws_vpc_security_group_rule
        WHERE
            type = 'ingress'
            AND cidr_ipv4 = '0.0.0.0/0'
            AND (
                (
                    ip_protocol = '-1'
                    AND from_port IS NULL
                )
                OR (
                    from_port >= 3389
                    AND to_port <= 3389
                )
            )
        GROUP BY
            group_id
    )
    SELECT
        sg.group_id AS resource,
        CASE
            WHEN ingress_rdp_rules.group_id IS NULL THEN 'ok'
            ELSE 'alarm'
        END AS status,
        CASE
            WHEN ingress_rdp_rules.group_id IS NULL THEN sg.group_id || ' ingress restricted for RDP from 0.0.0.0/0.'
            ELSE sg.group_id || ' contains ' || ingress_rdp_rules.num_rdp_rules || ' ingress rule(s) allowing RDP from 0.0.0.0/0.'
        END AS reason,
        region,
        account_id
    FROM
        aws_vpc_security_group AS sg
    LEFT JOIN
        ingress_rdp_rules ON ingress_rdp_rules.group_id = sg.group_id
    WHERE
        CASE
            WHEN ingress_rdp_rules.group_id IS NULL THEN 'ok'
            ELSE 'alarm'
        END = 'alarm';

    EOT
}   

#

query "vpc_security_group_restrict_ingress_tcp_udp_all" {
  title = "3.9 VPC security groups should restrict ingress TCP and UDP access from 0.0.0.0/0"
  sql = <<EOT
    WITH bad_rules AS (
        SELECT
            group_id,
            COUNT(*) AS num_bad_rules
        FROM
            aws_vpc_security_group_rule
        WHERE
            type = 'ingress'
            AND cidr_ipv4 = '0.0.0.0/0'
            AND (
                ip_protocol IN ('tcp', 'udp')
                OR (
                    ip_protocol = '-1'
                    AND from_port IS NULL
                )
            )
        GROUP BY
            group_id
    )
    SELECT
        sg.group_id AS resource,
        CASE
            WHEN bad_rules.group_id IS NULL THEN 'ok'
            ELSE 'alarm'
        END AS status,
        CASE
            WHEN bad_rules.group_id IS NULL THEN sg.group_id || ' does not allow ingress to TCP or UDP ports from 0.0.0.0/0.'
            ELSE sg.group_id || ' contains ' || bad_rules.num_bad_rules || ' rule(s) that allow ingress to TCP or UDP ports from 0.0.0.0/0.'
        END AS reason,
        region,
        account_id
    FROM
        aws_vpc_security_group AS sg
    LEFT JOIN
        bad_rules ON bad_rules.group_id = sg.group_id
    WHERE
        CASE
            WHEN bad_rules.group_id IS NULL THEN 'ok'
            ELSE 'alarm'
        END = 'alarm';

    EOT
}  

#

query "autoscaling_ec2_launch_configuration_no_sensitive_data" {
  title = "3.10 EC2 auto scaling group launch configurations user data should not have any sensitive data"
  sql = <<EOT
    SELECT
        launch_configuration_arn AS resource,
        CASE
            WHEN user_data LIKE ANY (ARRAY [ '%pass%', '%secret%', '%token%', '%key%' ])
            OR user_data ~ '(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]' THEN 'alarm'
            ELSE 'ok'
        END AS status,
        CASE
            WHEN user_data LIKE ANY (ARRAY [ '%pass%', '%secret%', '%token%', '%key%' ])
            OR user_data ~ '(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]' THEN title || ' has potential secret patterns in user data.'
            ELSE title || ' does not contain secret patterns in user data.'
        END AS reason,
        region,
        account_id
    FROM
        aws_ec2_launch_configuration
    WHERE
        CASE
            WHEN user_data LIKE ANY (ARRAY [ '%pass%', '%secret%', '%token%', '%key%' ])
            OR user_data ~ '(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]' THEN 'alarm'
            ELSE 'ok'
        END = 'alarm';

    EOT
}  

#

query "cloudformation_stack_output_no_secrets" {
  title = "3.11 CloudFormation stacks outputs should not have any secrets"
  sql = <<EOT
    WITH stack_output AS (
        SELECT
            id,
            jsonb_array_elements(outputs) -> 'OutputKey' AS k,
            jsonb_array_elements(outputs) -> 'OutputValue' AS v,
            region,
            account_id
        FROM
            aws_cloudformation_stack
    ),
    stack_with_secrets AS (
        SELECT
            DISTINCT id
        FROM
            stack_output
        WHERE
            LOWER(k :: TEXT) LIKE ANY (ARRAY [ '%pass%', '%secret%', '%token%', '%key%' ])
            OR k :: TEXT ~ '(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]'
            OR LOWER(v :: TEXT) LIKE ANY (ARRAY [ '%pass%', '%secret%', '%token%', '%key%' ])
            OR v :: TEXT ~ '(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]'
    )
    SELECT
        c.name AS resource,
        CASE
            WHEN c.outputs IS NULL THEN 'ok'
            WHEN s.id IS NULL THEN 'ok'
            ELSE 'alarm'
        END AS status,
        CASE
            WHEN c.outputs IS NULL THEN title || ' has no outputs.'
            WHEN s.id IS NULL THEN title || ' no secrets found in outputs.'
            ELSE title || ' has secrets in outputs.'
        END AS reason,
        c.region,
        c.account_id
    FROM
        aws_cloudformation_stack AS c
    LEFT JOIN stack_with_secrets AS s ON c.id = s.id
    WHERE
        CASE
            WHEN c.outputs IS NULL THEN 'ok'
            WHEN s.id IS NULL THEN 'ok'
            ELSE 'alarm'
        END = 'alarm';

    EOT
} 

#

query "ecs_task_definition_container_environment_no_secret" {
  title = "3.12 ECS task definition containers should not have secrets passed as environment variables"
  sql = <<EOT
    WITH definitions_with_secret_environment_variable AS (
        SELECT
            DISTINCT task_definition_arn AS arn
        FROM
            aws_ecs_task_definition,
            jsonb_array_elements(container_definitions) AS c,
            jsonb_array_elements(c -> 'Environment') AS e,
            jsonb_array_elements(
                CASE
                    jsonb_typeof(c -> 'Secrets')
                    WHEN 'array' THEN (c -> 'Secrets')
                    ELSE NULL
                END
            ) AS s
        WHERE
            e ->> 'Name' LIKE ANY (
                ARRAY [ 'AWS_ACCESS_KEY_ID',
                'AWS_SECRET_ACCESS_KEY',
                'ECS_ENGINE_AUTH_DATA' ]
            )
            OR s ->> 'Name' LIKE ANY (
                ARRAY [ 'AWS_ACCESS_KEY_ID',
                'AWS_SECRET_ACCESS_KEY',
                'ECS_ENGINE_AUTH_DATA' ]
            )
    )
    SELECT
        d.task_definition_arn AS resource,
        CASE
            WHEN e.arn IS NULL THEN 'ok'
            ELSE 'alarm'
        END AS status,
        CASE
            WHEN e.arn IS NULL THEN d.title || ' container environment variables does not have secrets.'
            ELSE d.title || ' container environment variables have secrets.'
        END AS reason,
        region,
        account_id
    FROM
        aws_ecs_task_definition AS d
    LEFT JOIN definitions_with_secret_environment_variable AS e ON d.task_definition_arn = e.arn
    WHERE
        CASE
            WHEN e.arn IS NULL THEN 'ok'
            ELSE 'alarm'
        END = 'alarm';

    EOT
} 

#

query "ec2_instance_no_launch_wizard_security_group" {
  title = "3.13 EC2 instances should not be attached to 'launch wizard' security groups"
  sql = <<EOT
    WITH launch_wizard_sg_attached_instance AS (
        SELECT
            DISTINCT arn AS arn
        FROM
            aws_ec2_instance,
            jsonb_array_elements(security_groups) AS sg
        WHERE
            sg ->> 'GroupName' LIKE 'launch-wizard%'
    )
    SELECT
        i.instance_id AS resource,
        CASE
            WHEN sg.arn IS NULL THEN 'ok'
            ELSE 'alarm'
        END AS status,
        CASE
            WHEN sg.arn IS NULL THEN i.title || ' not associated with launch-wizard security group.'
            ELSE i.title || ' associated with launch-wizard security group.'
        END AS reason,
        i.region,
        i.account_id
    FROM
        aws_ec2_instance AS i
    LEFT JOIN launch_wizard_sg_attached_instance AS sg ON i.arn = sg.arn
    WHERE
        CASE
            WHEN sg.arn IS NULL THEN 'ok'
            ELSE 'alarm'
        END = 'alarm';

    EOT
} 

#


query "iam_policy_no_star_star" {
  title = "3.14 IAM policy should not have statements with admin access"
  sql = <<EOT
    WITH bad_policies AS (
        SELECT
            arn,
            COUNT(*) AS num_bad_statements
        FROM
            aws_iam_policy,
            jsonb_array_elements(policy_std -> 'Statement') AS s,
            jsonb_array_elements_text(s -> 'Resource') AS resource,
            jsonb_array_elements_text(s -> 'Action') AS action
        WHERE
            NOT is_aws_managed
            AND s ->> 'Effect' = 'Allow'
            AND resource = '*'
            AND (
                action = '*'
                OR action = '*:*'
            )
        GROUP BY
            arn
    )
    SELECT
        p.name AS resource,
        'alarm' AS status,
        p.name || ' contains ' || COALESCE(bad.num_bad_statements, 0) || ' statements that allow action "*" on resource "*".'
            AS reason,
        p.account_id
    FROM
        aws_iam_policy AS p
    LEFT JOIN
        bad_policies AS bad ON p.arn = bad.arn
    WHERE
        NOT p.is_aws_managed;

    EOT
} 

#

query "rds_db_instance_prohibit_public_access" {
  title = "3.15 RDS DB instances should prohibit public access, determined by the PubliclyAccessible configuration"
  sql = <<EOT
    SELECT
        arn AS resource,
        CASE
            WHEN publicly_accessible THEN 'alarm'
            ELSE 'ok'
        END AS status,
        CASE
            WHEN publicly_accessible THEN title || ' publicly accessible.'
            ELSE title || ' not publicly accessible.'
        END AS reason,
        region,
        account_id
    FROM
        aws_rds_db_instance
    WHERE
        CASE
            WHEN publicly_accessible THEN 'alarm'
            ELSE 'ok'
        END = 'alarm';

    EOT
} 

#

query "s3_bucket_policy_restricts_cross_account_permission_changes" {
  title = "3.16 S3 permissions granted to other AWS accounts in bucket policies should be restricted"
  sql = <<EOT
    WITH cross_account_buckets AS (
        SELECT DISTINCT arn
        FROM aws_s3_bucket,
            jsonb_array_elements(policy_std -> 'Statement') AS s,
            jsonb_array_elements_text(s -> 'Principal' -> 'AWS') AS p,
            string_to_array(p, ':') AS pa,
            jsonb_array_elements_text(s -> 'Action') AS a
        WHERE s ->> 'Effect' = 'Allow'
            AND (pa[5] != account_id OR p = '*')
            AND a IN (
                's3:deletebucketpolicy',
                's3:putbucketacl',
                's3:putbucketpolicy',
                's3:putencryptionconfiguration',
                's3:putobjectacl'
            )
    )
    SELECT
        a.arn AS resource,
        CASE
            WHEN b.arn IS NULL THEN 'ok'
            ELSE 'alarm'
        END AS status,
        CASE
            WHEN b.arn IS NULL THEN title || ' restricts cross-account bucket access.'
            ELSE title || ' allows cross-account bucket access.'
        END AS reason,
        a.region,
        a.account_id
    FROM
        aws_s3_bucket a
    LEFT JOIN
        cross_account_buckets b ON a.arn = b.arn
    WHERE
        CASE
            WHEN b.arn IS NULL THEN 'ok'
            ELSE 'alarm'
        END = 'alarm';

    EOT
} 

#

query "s3_bucket_restrict_public_read_access" {
  title = "3.17 S3 buckets should prohibit public read access"
  sql = <<EOT
    WITH public_acl AS (
        SELECT DISTINCT name
        FROM aws_s3_bucket,
            jsonb_array_elements(acl -> 'Grants') AS grants
        WHERE (grants -> 'Grantee' ->> 'URI' = 'http://acs.amazonaws.com/groups/global/AllUsers'
                OR grants -> 'Grantee' ->> 'URI' = 'http://acs.amazonaws.com/groups/global/AuthenticatedUsers')
            AND (grants ->> 'Permission' = 'FULL_query'
                OR grants ->> 'Permission' = 'READ_ACP'
                OR grants ->> 'Permission' = 'READ')
    ),
    read_access_policy AS (
        SELECT DISTINCT name
        FROM aws_s3_bucket,
            jsonb_array_elements(policy_std -> 'Statement') AS s,
            jsonb_array_elements_text(s -> 'Action') AS action
        WHERE s ->> 'Effect' = 'Allow'
            AND (s -> 'Principal' -> 'AWS' = '["*"]'
                OR s ->> 'Principal' = '*')
            AND (action = '*' OR action = '*:*' OR action = 's3:*'
                OR action ILIKE 's3:get%' OR action ILIKE 's3:list%')
    )
    SELECT
        b.arn AS resource,
        CASE
            WHEN (
                block_public_acls OR a.name IS NULL
            )
            AND NOT bucket_policy_is_public THEN 'ok'
            WHEN (
                block_public_acls OR a.name IS NULL
            )
            AND (
                bucket_policy_is_public AND block_public_policy
            ) THEN 'ok'
            WHEN (
                block_public_acls OR a.name IS NULL
            )
            AND (
                bucket_policy_is_public AND p.name IS NULL
            ) THEN 'ok'
            ELSE 'alarm'
        END AS status,
        CASE
            WHEN (
                block_public_acls OR a.name IS NULL
            )
            AND NOT bucket_policy_is_public THEN b.title || ' not publicly readable.'
            WHEN (
                block_public_acls OR a.name IS NULL
            )
            AND (
                bucket_policy_is_public AND block_public_policy
            ) THEN b.title || ' not publicly readable.'
            WHEN (
                block_public_acls OR a.name IS NULL
            )
            AND (
                bucket_policy_is_public AND p.name IS NULL
            ) THEN b.title || ' not publicly readable.'
            ELSE b.title || ' publicly readable.'
        END AS reason,
        b.region,
        b.account_id
    FROM
        aws_s3_bucket AS b
    LEFT JOIN
        public_acl AS a ON b.name = a.name
    LEFT JOIN
        read_access_policy AS p ON b.name = p.name
    WHERE
        CASE
            WHEN (
                block_public_acls OR a.name IS NULL
            )
            AND NOT bucket_policy_is_public THEN 'ok'
            WHEN (
                block_public_acls OR a.name IS NULL
            )
            AND (
                bucket_policy_is_public AND block_public_policy
            ) THEN 'ok'
            WHEN (
                block_public_acls OR a.name IS NULL
            )
            AND (
                bucket_policy_is_public AND p.name IS NULL
            ) THEN 'ok'
            ELSE 'alarm'
        END = 'alarm';

    EOT
} 

#

query "s3_bucket_restrict_public_write_access" {
  title = "3.18 S3 buckets should prohibit public write access"
  sql = <<EOT
    WITH public_acl AS (
        SELECT DISTINCT name
        FROM aws_s3_bucket,
            jsonb_array_elements(acl -> 'Grants') AS grants
        WHERE (grants -> 'Grantee' ->> 'URI' = 'http://acs.amazonaws.com/groups/global/AllUsers'
                OR grants -> 'Grantee' ->> 'URI' = 'http://acs.amazonaws.com/groups/global/AuthenticatedUsers')
            AND (grants ->> 'Permission' = 'FULL_query'
                OR grants ->> 'Permission' = 'WRITE_ACP'
                OR grants ->> 'Permission' = 'WRITE')
    ),
    write_access_policy AS (
        SELECT DISTINCT name
        FROM aws_s3_bucket,
            jsonb_array_elements(policy_std -> 'Statement') AS s,
            jsonb_array_elements_text(s -> 'Action') AS action
        WHERE s ->> 'Effect' = 'Allow'
            AND (s -> 'Principal' -> 'AWS' = '["*"]'
                OR s ->> 'Principal' = '*')
            AND (action = '*' OR action = '*:*' OR action = 's3:*'
                OR action ILIKE 's3:put%' OR action ILIKE 's3:delete%'
                OR action ILIKE 's3:create%' OR action ILIKE 's3:update%'
                OR action ILIKE 's3:replicate%' OR action ILIKE 's3:restore%')
    )
    SELECT
        b.arn AS resource,
        CASE
            WHEN (
                block_public_acls OR a.name IS NULL
            )
            AND NOT bucket_policy_is_public THEN 'ok'
            WHEN (
                block_public_acls OR a.name IS NULL
            )
            AND (
                bucket_policy_is_public AND block_public_policy
            ) THEN 'ok'
            WHEN bucket_policy_is_public AND p.name IS NULL THEN 'ok'
            ELSE 'alarm'
        END AS status,
        CASE
            WHEN (
                block_public_acls OR a.name IS NULL
            )
            AND NOT bucket_policy_is_public THEN b.title || ' not publicly writable.'
            WHEN (
                block_public_acls OR a.name IS NULL
            )
            AND (
                bucket_policy_is_public AND block_public_policy
            ) THEN b.title || ' not publicly writable.'
            WHEN (
                block_public_acls OR a.name IS NULL
            )
            AND (
                bucket_policy_is_public AND p.name IS NULL
            ) THEN b.title || ' not publicly writable.'
            ELSE b.title || ' publicly writable.'
        END AS reason,
        b.region,
        b.account_id
    FROM
        aws_s3_bucket AS b
    LEFT JOIN
        public_acl AS a ON b.name = a.name
    LEFT JOIN
        write_access_policy AS p ON b.name = p.name
    WHERE
        CASE
            WHEN (
                block_public_acls OR a.name IS NULL
            )
            AND NOT bucket_policy_is_public THEN 'ok'
            WHEN (
                block_public_acls OR a.name IS NULL
            )
            AND (
                bucket_policy_is_public AND block_public_policy
            ) THEN 'ok'
            WHEN bucket_policy_is_public AND p.name IS NULL THEN 'ok'
            ELSE 'alarm'
        END = 'alarm';

    EOT
} 

#

query "s3_public_access_block_bucket_account" {
  title = "3.19 S3 public access should be blocked at account level"
  sql = <<EOT
    SELECT
        arn AS resource,
        CASE
            WHEN (
                bucket.block_public_acls OR s3account.block_public_acls
            )
            AND (
                bucket.block_public_policy OR s3account.block_public_policy
            )
            AND (
                bucket.ignore_public_acls OR s3account.ignore_public_acls
            )
            AND (
                bucket.restrict_public_buckets OR s3account.restrict_public_buckets
            ) THEN 'ok'
            ELSE 'alarm'
        END AS status,
        CASE
            WHEN (
                bucket.block_public_acls OR s3account.block_public_acls
            )
            AND (
                bucket.block_public_policy OR s3account.block_public_policy
            )
            AND (
                bucket.ignore_public_acls OR s3account.ignore_public_acls
            )
            AND (
                bucket.restrict_public_buckets OR s3account.restrict_public_buckets
            ) THEN name || ' all public access blocks enabled.'
            ELSE name || ' not enabled for: ' || CONCAT_WS(
                ', ',
                CASE
                    WHEN NOT (
                        bucket.block_public_acls OR s3account.block_public_acls
                    ) THEN 'block_public_acls'
                END,
                CASE
                    WHEN NOT (
                        bucket.block_public_policy OR s3account.block_public_policy
                    ) THEN 'block_public_policy'
                END,
                CASE
                    WHEN NOT (
                        bucket.ignore_public_acls OR s3account.ignore_public_acls
                    ) THEN 'ignore_public_acls'
                END,
                CASE
                    WHEN NOT (
                        bucket.restrict_public_buckets OR s3account.restrict_public_buckets
                    ) THEN 'restrict_public_buckets'
                END
            ) || '.'
        END AS reason,
        bucket.region,
        bucket.account_id
    FROM
        aws_s3_bucket AS bucket
    INNER JOIN
        aws_s3_account_settings AS s3account ON s3account.account_id = bucket.account_id
    WHERE
        CASE
            WHEN (
                bucket.block_public_acls OR s3account.block_public_acls
            )
            AND (
                bucket.block_public_policy OR s3account.block_public_policy
            )
            AND (
                bucket.ignore_public_acls OR s3account.ignore_public_acls
            )
            AND (
                bucket.restrict_public_buckets OR s3account.restrict_public_buckets
            ) THEN 'ok'
            ELSE 'alarm'
        END = 'alarm';


    EOT
} 

#

query "sqs_queue_policy_prohibit_public_access" {
  title = "3.20 SQS queue policies should prohibit public access"
  sql = <<EOT
    WITH wildcard_action_policies AS (
        SELECT
            queue_arn,
            COUNT(*) AS statements_num
        FROM
            aws_sqs_queue,
            JSONB_ARRAY_ELEMENTS(policy_std -> 'Statement') AS s
        WHERE
            s ->> 'Effect' = 'Allow' -- aws:SourceOwner
            AND s -> 'Condition' -> 'StringEquals' -> 'aws:sourceowner' IS NULL
            AND s -> 'Condition' -> 'StringEqualsIgnoreCase' -> 'aws:sourceowner' IS NULL
            AND (
                s -> 'Condition' -> 'StringLike' -> 'aws:sourceowner' IS NULL
                OR s -> 'Condition' -> 'StringLike' -> 'aws:sourceowner' ? '*'
            ) -- aws:SourceAccount
            AND s -> 'Condition' -> 'StringEquals' -> 'aws:sourceaccount' IS NULL
            AND s -> 'Condition' -> 'StringEqualsIgnoreCase' -> 'aws:sourceaccount' IS NULL
            AND (
                s -> 'Condition' -> 'StringLike' -> 'aws:sourceaccount' IS NULL
                OR s -> 'Condition' -> 'StringLike' -> 'aws:sourceaccount' ? '*'
            ) -- aws:PrincipalOrgID
            AND s -> 'Condition' -> 'StringEquals' -> 'aws:principalorgid' IS NULL
            AND s -> 'Condition' -> 'StringEqualsIgnoreCase' -> 'aws:principalorgid' IS NULL
            AND (
                s -> 'Condition' -> 'StringLike' -> 'aws:principalorgid' IS NULL
                OR s -> 'Condition' -> 'StringLike' -> 'aws:principalorgid' ? '*'
            ) -- aws:PrincipalAccount
            AND s -> 'Condition' -> 'StringEquals' -> 'aws:principalaccount' IS NULL
            AND s -> 'Condition' -> 'StringEqualsIgnoreCase' -> 'aws:principalaccount' IS NULL
            AND (
                s -> 'Condition' -> 'StringLike' -> 'aws:principalaccount' IS NULL
                OR s -> 'Condition' -> 'StringLike' -> 'aws:principalaccount' ? '*'
            ) -- aws:PrincipalArn
            AND s -> 'Condition' -> 'StringEquals' -> 'aws:principalarn' IS NULL
            AND s -> 'Condition' -> 'StringEqualsIgnoreCase' -> 'aws:principalarn' IS NULL
            AND (
                s -> 'Condition' -> 'StringLike' -> 'aws:principalarn' IS NULL
                OR s -> 'Condition' -> 'StringLike' -> 'aws:principalarn' ? '*'
            )
            AND (
                s -> 'Condition' -> 'ArnEquals' -> 'aws:principalarn' IS NULL
                OR s -> 'Condition' -> 'ArnEquals' -> 'aws:principalarn' ? '*'
            )
            AND (
                s -> 'Condition' -> 'ArnLike' -> 'aws:principalarn' IS NULL
                OR s -> 'Condition' -> 'ArnLike' -> 'aws:principalarn' ? '*'
            ) -- aws:SourceArn
            AND s -> 'Condition' -> 'StringEquals' -> 'aws:sourcearn' IS NULL
            AND s -> 'Condition' -> 'StringEqualsIgnoreCase' -> 'aws:sourcearn' IS NULL
            AND (
                s -> 'Condition' -> 'StringLike' -> 'aws:sourcearn' IS NULL
                OR s -> 'Condition' -> 'StringLike' -> 'aws:sourcearn' ? '*'
            )
            AND (
                s -> 'Condition' -> 'ArnEquals' -> 'aws:sourcearn' IS NULL
                OR s -> 'Condition' -> 'ArnEquals' -> 'aws:sourcearn' ? '*'
            )
            AND (
                s -> 'Condition' -> 'ArnLike' -> 'aws:sourcearn' IS NULL
                OR s -> 'Condition' -> 'ArnLike' -> 'aws:sourcearn' ? '*'
            )
            AND (
                s -> 'Principal' ->> 'AWS' = '["*"]'
                OR s ->> 'Principal' = '*'
            )
        GROUP BY
            queue_arn
    )
    SELECT
        r.queue_arn AS resource,
        CASE
            WHEN r.policy IS NULL THEN 'info'
            WHEN p.queue_arn IS NULL THEN 'ok'
            ELSE 'alarm'
        END AS status,
        CASE
            WHEN r.policy IS NULL THEN title || ' does not have a defined policy or has insufficient access to the policy.'
            WHEN p.queue_arn IS NULL THEN title || ' policy does not allow public access.'
            ELSE title || ' policy contains ' || COALESCE(p.statements_num, 0) || ' statement(s) that allow public access.'
        END AS reason,
        region,
        account_id
    FROM
        aws_sqs_queue AS r
    LEFT JOIN
        wildcard_action_policies AS p ON p.queue_arn = r.queue_arn
    WHERE
        p.queue_arn IS NOT NULL
        OR r.policy IS NULL;


    EOT
} 

#

query "sns_topic_policy_prohibit_subscription_access" {
  title = "3.21 SNS topic policies should prohibit public access"
  sql = <<EOT
    WITH wildcard_action_policies AS (
        SELECT
            topic_arn,
            COUNT(*) AS statements_num
        FROM
            aws_sns_topic,
            JSONB_ARRAY_ELEMENTS(policy_std -> 'Statement') AS s,
            JSONB_ARRAY_ELEMENTS_TEXT(s -> 'Action') AS a
        WHERE
            s ->> 'Effect' = 'Allow'
            AND (
                (s -> 'Principal' -> 'AWS') = '["*"]'
                OR s ->> 'Principal' = '*'
            )
            AND a IN ('sns:subscribe', 'sns:receive')
            AND s -> 'Condition' IS NULL
        GROUP BY
            topic_arn
    )
    SELECT
        t.topic_arn AS resource,
        CASE
            WHEN p.topic_arn IS NULL THEN 'ok'
            ELSE 'alarm'
        END AS status,
        CASE
            WHEN p.topic_arn IS NULL THEN title || ' does not allow subscribe access without condition.'
            ELSE title || ' contains ' || COALESCE(p.statements_num, 0) || ' statements that allow subscribe access without condition.'
        END AS reason,
        t.region,
        t.account_id
    FROM
        aws_sns_topic AS t
    LEFT JOIN
        wildcard_action_policies AS p ON p.topic_arn = t.topic_arn
    WHERE
        p.topic_arn IS NOT NULL;

    EOT
} 

#

query "ec2_ami_restrict_public_access" {
  title = "3.22 EC2 AMIs should restrict public access"
  sql = <<EOT
    SELECT
        'arn:' || partition || ':ec2:' || region || ':' || account_id || ':image/' || image_id as resource,
        'alarm' AS status,
        title || ' publicly accessible.' AS reason,
        region,
        account_id
    FROM
        aws_ec2_ami
    WHERE
        public;

    EOT
} 

#

query "ec2_instance_not_publicly_accessible" {
  title = "3.23 EC2 instances should not have a public IP address"
  sql = <<EOT
    SELECT
        instance_id AS resource,
        'alarm' AS status,
        CASE
            WHEN public_ip_address IS NULL THEN instance_id || ' not publicly accessible.'
            ELSE instance_id || ' publicly accessible.'
        END AS reason,
        region,
        account_id
    FROM
        aws_ec2_instance
    WHERE
        public_ip_address IS NOT NULL;

    EOT
} 

#

query "ecr_repository_prohibit_public_access" {
  title = "3.24. ECR repositories should prohibit public access"
  sql = <<EOT
    WITH open_access_ecr_repo AS (
        SELECT
            DISTINCT arn
        FROM
            aws_ecr_repository,
            JSONB_ARRAY_ELEMENTS(policy_std -> 'Statement') AS s,
            JSONB_ARRAY_ELEMENTS_TEXT(s -> 'Principal' -> 'AWS') AS p,
            STRING_TO_ARRAY(p, ':') AS pa,
            JSONB_ARRAY_ELEMENTS_TEXT(s -> 'Action') AS a
        WHERE
            s ->> 'Effect' = 'Allow'
            AND (p = '*')
    )
    SELECT
        r.arn AS resource,
        'alarm' AS status,
        CASE
            WHEN o.arn IS NOT NULL THEN r.title || ' allows public access.'
            ELSE r.title || ' does not allow public access.'
        END AS reason,
        r.region,
        r.account_id
    FROM
        aws_ecr_repository AS r
    LEFT JOIN
        open_access_ecr_repo AS o ON r.arn = o.arn
    WHERE
        o.arn IS NOT NULL;

    EOT
} 


#

query "vpc_security_group_restricted_common_ports" {
  title = "3.25 Security groups should not allow unrestricted access to ports with high risk"
  sql = <<EOT
    WITH ingress_ssh_rules AS (
        SELECT
            group_id,
            COUNT(*) AS num_ssh_rules
        FROM
            aws_vpc_security_group_rule
        WHERE
            type = 'ingress'
            AND cidr_ipv4 = '0.0.0.0/0'
            AND (
                (
                    ip_protocol = '-1'
                    AND from_port IS NULL
                )
                OR (
                    from_port >= 22
                    AND to_port <= 22
                )
                OR (
                    from_port >= 3389
                    AND to_port <= 3389
                )
                OR (
                    from_port >= 21
                    AND to_port <= 21
                )
                OR (
                    from_port >= 20
                    AND to_port <= 20
                )
                OR (
                    from_port >= 3306
                    AND to_port <= 3306
                )
                OR (
                    from_port >= 4333
                    AND to_port <= 4333
                )
                OR (
                    from_port >= 23
                    AND to_port <= 23
                )
                OR (
                    from_port >= 25
                    AND to_port <= 25
                )
                OR (
                    from_port >= 445
                    AND to_port <= 445
                )
                OR (
                    from_port >= 110
                    AND to_port <= 110
                )
                OR (
                    from_port >= 135
                    AND to_port <= 135
                )
                OR (
                    from_port >= 143
                    AND to_port <= 143
                )
                OR (
                    from_port >= 1433
                    AND to_port <= 3389
                )
                OR (
                    from_port >= 3389
                    AND to_port <= 1434
                )
                OR (
                    from_port >= 5432
                    AND to_port <= 5432
                )
                OR (
                    from_port >= 5500
                    AND to_port <= 5500
                )
                OR (
                    from_port >= 5601
                    AND to_port <= 5601
                )
                OR (
                    from_port >= 9200
                    AND to_port <= 9300
                )
                OR (
                    from_port >= 8080
                    AND to_port <= 8080
                )
            )
        GROUP BY
            group_id
    )
    SELECT
        sg.group_id AS resource,
        'alarm' AS status,
        sg.group_id || ' contains ' || COALESCE(ingress_ssh_rules.num_ssh_rules, 0) || ' ingress rule(s) allowing access for common ports from 0.0.0.0/0.' AS reason,
        sg.region,
        sg.account_id
    FROM
        aws_vpc_security_group AS sg
    LEFT JOIN
        ingress_ssh_rules ON ingress_ssh_rules.group_id = sg.group_id
    WHERE
        ingress_ssh_rules.group_id IS NOT NULL;

    EOT
} 

#

query "iam_role_trust_policy_prohibit_public_access" {
  title = "3.26 IAM role trust policies should prohibit public access"
  sql = <<EOT
    WITH wildcard_action_policies AS (
        SELECT
            arn,
            COUNT(*) AS statements_num
        FROM
            aws_iam_role,
            JSONB_ARRAY_ELEMENTS(assume_role_policy_std -> 'Statement') AS s
        WHERE
            s ->> 'Effect' = 'Allow' -- aws:SourceOwner
            AND s -> 'Condition' -> 'StringEquals' -> 'aws:sourceowner' IS NULL
            AND s -> 'Condition' -> 'StringEqualsIgnoreCase' -> 'aws:sourceowner' IS NULL
            AND (
                s -> 'Condition' -> 'StringLike' -> 'aws:sourceowner' IS NULL
                OR s -> 'Condition' -> 'StringLike' -> 'aws:sourceowner' ? '*'
            ) -- aws:SourceAccount
            AND s -> 'Condition' -> 'StringEquals' -> 'aws:sourceaccount' IS NULL
            AND s -> 'Condition' -> 'StringEqualsIgnoreCase' -> 'aws:sourceaccount' IS NULL
            AND (
                s -> 'Condition' -> 'StringLike' -> 'aws:sourceaccount' IS NULL
                OR s -> 'Condition' -> 'StringLike' -> 'aws:sourceaccount' ? '*'
            ) -- aws:PrincipalOrgID
            AND s -> 'Condition' -> 'StringEquals' -> 'aws:principalorgid' IS NULL
            AND s -> 'Condition' -> 'StringEqualsIgnoreCase' -> 'aws:principalorgid' IS NULL
            AND (
                s -> 'Condition' -> 'StringLike' -> 'aws:principalorgid' IS NULL
                OR s -> 'Condition' -> 'StringLike' -> 'aws:principalorgid' ? '*'
            ) -- aws:PrincipalAccount
            AND s -> 'Condition' -> 'StringEquals' -> 'aws:principalaccount' IS NULL
            AND s -> 'Condition' -> 'StringEqualsIgnoreCase' -> 'aws:principalaccount' IS NULL
            AND (
                s -> 'Condition' -> 'StringLike' -> 'aws:principalaccount' IS NULL
                OR s -> 'Condition' -> 'StringLike' -> 'aws:principalaccount' ? '*'
            ) -- aws:PrincipalArn
            AND s -> 'Condition' -> 'StringEquals' -> 'aws:principalarn' IS NULL
            AND s -> 'Condition' -> 'StringEqualsIgnoreCase' -> 'aws:principalarn' IS NULL
            AND (
                s -> 'Condition' -> 'StringLike' -> 'aws:principalarn' IS NULL
                OR s -> 'Condition' -> 'StringLike' -> 'aws:principalarn' ? '*'
            )
            AND s -> 'Condition' -> 'ArnEquals' -> 'aws:principalarn' IS NULL
            AND (
                s -> 'Condition' -> 'ArnLike' -> 'aws:principalarn' IS NULL
                OR s -> 'Condition' -> 'ArnLike' -> 'aws:principalarn' ? '*'
            ) -- aws:SourceArn
            AND s -> 'Condition' -> 'StringEquals' -> 'aws:sourcearn' IS NULL
            AND s -> 'Condition' -> 'StringEqualsIgnoreCase' -> 'aws:sourcearn' IS NULL
            AND (
                s -> 'Condition' -> 'StringLike' -> 'aws:sourcearn' IS NULL
                OR s -> 'Condition' -> 'StringLike' -> 'aws:sourcearn' ? '*'
            )
            AND s -> 'Condition' -> 'ArnEquals' -> 'aws:sourcearn' IS NULL
            AND (
                s -> 'Condition' -> 'ArnLike' -> 'aws:sourcearn' IS NULL
                OR s -> 'Condition' -> 'ArnLike' -> 'aws:sourcearn' ? '*'
            )
            AND (
                s -> 'Principal' ->> 'AWS' = '["*"]'
                OR s ->> 'Principal' = '*'
            )
        GROUP BY
            arn
    )
    SELECT
        r.arn AS resource,
        'alarm' AS status,
        title || ' trust policy contains ' || COALESCE(p.statements_num, 0) || ' statement(s) that allow public access.' AS reason,
        r.region,
        r.account_id
    FROM
        aws_iam_role AS r
    LEFT JOIN
        wildcard_action_policies AS p ON p.arn = r.arn
    WHERE
        p.arn IS NOT NULL;


    EOT
} 

#
query "cloudtrail_bucket_not_public" {
  title = "3.27 Ensure the S3 bucket CloudTrail logs to is not publicly accessible"
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


query "efs_file_system_restrict_public_access" {
  title = "3.28 EFS file systems should restrict public access"
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

query "elb_application_classic_network_lb_prohibit_public_access" {
  title = "3.29 ELB load balancers should prohibit public access"
  sql = <<EOT
    WITH all_lb_details AS (
        SELECT
            arn,
            scheme,
            title,
            region,
            account_id,
            tags,
            _ctx
        FROM
            aws_ec2_application_load_balancer
        UNION
        SELECT
            arn,
            scheme,
            title,
            region,
            account_id,
            tags,
            _ctx
        FROM
            aws_ec2_network_load_balancer
        UNION
        SELECT
            arn,
            scheme,
            title,
            region,
            account_id,
            tags,
            _ctx
        FROM
            aws_ec2_classic_load_balancer
    )
    SELECT
        arn AS resource,
        CASE
            WHEN scheme = 'internet-facing' THEN 'alarm'
            ELSE 'ok'
        END AS status,
        CASE
            WHEN scheme = 'internet-facing' THEN title || ' is publicly accessible.'
            ELSE title || ' is not publicly accessible.'
        END AS reason,
        region,
        account_id
    FROM
        all_lb_details
    WHERE
        scheme = 'internet-facing';

    EOT
} 

#

query "ssm_document_prohibit_public_access" {
  title = "3.30 SSM documents should not be public"
  sql = <<EOT
    SELECT
        'arn:' || partition || ':ssm:' || region || ':' || account_id || ':document/' || name AS resource,
        CASE
            WHEN account_ids::jsonb ? 'all' THEN 'alarm'
            ELSE 'ok'
        END AS status,
        CASE
            WHEN account_ids::jsonb ? 'all' THEN title || ' is publicly accessible.'
            ELSE title || ' is not publicly accessible.'
        END AS reason,
        region,
        account_id
    FROM
        aws_ssm_document
    WHERE
        owner_type = 'Self' AND account_ids::jsonb ? 'all';

    EOT
} 

#

query "ebs_attached_volume_encryption_enabled" {
  title = "3.31 Attached EBS volumes should have encryption enabled"
  sql = <<EOT
    SELECT
        arn AS resource,
        CASE
            WHEN state != 'in-use' THEN 'skip'
            WHEN encrypted THEN 'ok'
            ELSE 'alarm'
        END AS status,
        CASE
            WHEN state != 'in-use' THEN volume_id || ' not attached.'
            WHEN encrypted THEN volume_id || ' encrypted.'
            ELSE volume_id || ' not encrypted.'
        END AS reason,
        region,
        account_id
    FROM
        aws_ebs_volume
    WHERE
        state = 'in-use' AND NOT encrypted;

    EOT
} 

#

query "kms_cmk_policy_prohibit_public_access" {
  title = "3.32 KMS CMK policies should prohibit public access"
  sql = <<EOT
    WITH wildcard_action_policies AS (
        SELECT
            arn,
            COUNT(*) AS statements_num
        FROM
            aws_kms_key,
            JSONB_ARRAY_ELEMENTS(policy_std -> 'Statement') AS s
        WHERE
            s ->> 'Effect' = 'Allow'
            AND (
                (s -> 'Principal' ->> 'AWS') = '["*"]'
                OR s ->> 'Principal' = '*'
            )
            AND key_manager = 'CUSTOMER'
        GROUP BY
            arn
    )
    SELECT
        k.arn AS resource,
        CASE
            WHEN p.arn IS NULL THEN 'ok'
            ELSE 'alarm'
        END AS status,
        CASE
            WHEN p.arn IS NULL THEN title || ' does not allow public access.'
            ELSE title || ' contains ' || COALESCE(p.statements_num, 0) || ' statements that allow public access.'
        END AS reason,
        k.region,
        k.account_id
    FROM
        aws_kms_key AS k
    LEFT JOIN
        wildcard_action_policies AS p ON p.arn = k.arn
    WHERE
        key_manager = 'CUSTOMER' AND (p.arn IS NOT NULL OR statements_num > 0);

    EOT
} 

#

query "lambda_function_restrict_public_access" {
  title = "3.33 Lambda functions should restrict public access"
  sql = <<EOT
    WITH wildcard_action_policies AS (
        SELECT
            arn,
            COUNT(*) AS statements_num
        FROM
            aws_lambda_function,
            JSONB_ARRAY_ELEMENTS(policy_std -> 'Statement') AS s
        WHERE
            s ->> 'Effect' = 'Allow'
            AND (
                (s -> 'Principal' ->> 'AWS') = '["*"]'
                OR s ->> 'Principal' = '*'
            )
        GROUP BY
            arn
    )
    SELECT
        f.arn AS resource,
        CASE
            WHEN p.arn IS NULL THEN 'ok'
            ELSE 'alarm'
        END AS status,
        CASE
            WHEN p.arn IS NULL THEN title || ' does not allow public access.'
            ELSE title || ' contains ' || COALESCE(p.statements_num, 0) || ' statements that allow public access.'
        END AS reason,
        f.region,
        f.account_id
    FROM
        aws_lambda_function AS f
    LEFT JOIN
        wildcard_action_policies AS p ON p.arn = f.arn
    WHERE
        p.arn IS NOT NULL;

    EOT
} 

#

query "eks_cluster_endpoint_public_access_restricted" {
  title = "3.34 EKS clusters endpoint should restrict public access"
  sql = <<EOT
    SELECT
        arn AS resource,
        CASE
            WHEN resources_vpc_config ->> 'EndpointPrivateAccess' = 'true' AND resources_vpc_config ->> 'EndpointPublicAccess' = 'false' THEN 'ok'
            WHEN resources_vpc_config ->> 'EndpointPublicAccess' = 'true' AND resources_vpc_config -> 'PublicAccessCidrs' @> '["0.0.0.0/0"]' THEN 'alarm'
            ELSE 'ok'
        END AS status,
        CASE
            WHEN resources_vpc_config ->> 'EndpointPrivateAccess' = 'true' AND resources_vpc_config ->> 'EndpointPublicAccess' = 'false' THEN title || ' endpoint access is private.'
            WHEN resources_vpc_config ->> 'EndpointPublicAccess' = 'true' AND resources_vpc_config -> 'PublicAccessCidrs' @> '["0.0.0.0/0"]' THEN title || ' endpoint access is public.'
            ELSE title || ' endpoint public access is restricted.'
        END AS reason,
        region,
        account_id
    FROM
        aws_eks_cluster
    WHERE
        resources_vpc_config ->> 'EndpointPublicAccess' = 'true' AND resources_vpc_config -> 'PublicAccessCidrs' @> '["0.0.0.0/0"]';

    EOT
} 

#

query "eks_cluster_secrets_encrypted" {
  title = "3.35 EKS clusters should be configured to have kubernetes secrets encrypted using KMS"
  sql = <<EOT
    WITH eks_secrets_encrypted AS (
        SELECT
            DISTINCT arn AS arn
        FROM
            aws_eks_cluster,
            JSONB_ARRAY_ELEMENTS(encryption_config) AS e
        WHERE
            e -> 'Resources' @> '["secrets"]'
    )
    SELECT
        a.arn AS resource,
        'alarm' AS status,
        CASE
            WHEN encryption_config IS NULL THEN a.title || ' encryption not enabled.'
            ELSE a.title || ' not encrypted with EKS secrets.'
        END AS reason,
        region,
        account_id
    FROM
        aws_eks_cluster AS a
    LEFT JOIN
        eks_secrets_encrypted AS b ON a.arn = b.arn
    WHERE
        encryption_config IS NULL OR b.arn IS NULL;

    EOT
} 

#eks_cluster_control_plane_audit_logging_enabled

query "eks_cluster_control_plane_audit_logging_enabled" {
  title = "3.36 EKS clusters should have query plane audit logging enabled"
  sql = <<EOT
    WITH query_panel_audit_logging AS (
        SELECT
            DISTINCT arn,
            log -> 'Types' AS log_type
        FROM
            aws_eks_cluster,
            JSONB_ARRAY_ELEMENTS(logging -> 'ClusterLogging') AS log
        WHERE
            log ->> 'Enabled' = 'true'
            AND (log -> 'Types') @> '["api", "audit", "authenticator", "querylerManager", "scheduler"]'
    )
    SELECT
        c.arn AS resource,
        'alarm' AS status,
        CASE
            WHEN logging -> 'ClusterLogging' @> '[{"Enabled": true}]' THEN c.title || ' query plane audit logging not enabled for all log types.'
            ELSE c.title || ' query plane audit logging not enabled.'
        END AS reason,
        c.region,
        c.account_id
    FROM
        aws_eks_cluster AS c
    LEFT JOIN
        query_panel_audit_logging AS l ON l.arn = c.arn
    WHERE
        l.arn IS NULL;

    EOT
} 

#

query "cloudfront_distribution_no_non_existent_s3_origin" {
  title = "3.37 CloudFront distributions should not point to non-existent S3 origins"
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
        aws_cloudfront_distribution as d
        left join jsonb_array_elements(d.origins) as o on true
        left join aws_s3_bucket as b on b.name = split_part(o ->> 'Id', '.s3', 1)
    where
        b.name is null
        and o ->> 'DomainName' like '%.s3.%'
    group by
        d.arn
    )
    select
    distinct d.arn as resource,
    case
        when b.arn is null then 'ok'
        else 'alarm'
    end as status,
    case
        when b.arn is null then 'Does not point to any non-existent S3 origins.'
        when jsonb_array_length(b.bucket_name_list) > 0 then
        case
            when jsonb_array_length(b.bucket_name_list) > 2 then concat(
            'Points to non-existent S3 origins: ',
            (b.bucket_name_list -> 0),
            ', ',
            (b.bucket_name_list -> 1),
            ' and ' || (jsonb_array_length(b.bucket_name_list) - 2) :: text || ' more.'
            )
            when jsonb_array_length(b.bucket_name_list) = 2 then concat(
            'Points to non-existent S3 origins: ',
            (b.bucket_name_list -> 0),
            ' and ',
            (b.bucket_name_list -> 1),
            '.'
            )
            else concat(
            'Points to non-existent S3 origin: ',
            (b.bucket_name_list -> 0),
            '.'
            )
        end
    end as reason,
    d.region,
    d.account_id
    from
    aws_cloudfront_distribution as d
    left join distribution_with_non_existent_bucket as b on b.arn = d.arn;

    EOT
} 

#

query "ecr_repository_image_scan_on_push_enabled" {
  title = "3.38 ECR private repositories should have image scanning configured"
  sql = <<EOT
    SELECT
        arn AS resource,
        'alarm' AS status,
        title || ' scan on push disabled.' AS reason,
        region,
        account_id
    FROM
        aws_ecr_repository
    WHERE
        image_scanning_configuration ->> 'ScanOnPush' = 'false';

    EOT
} 

#

query "ecs_task_definition_container_readonly_root_filesystem" {
  title = "3.39 ECS containers should be limited to read-only access to root filesystems"
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

query "eks_cluster_with_latest_kubernetes_version" {
  title = "3.40 EKS clusters should run on a supported Kubernetes version"
  sql = <<EOT
    SELECT
        arn AS resource,
        'alarm' AS status,
        title || ' does not run on a supported Kubernetes version.' AS reason,
        region,
        account_id
    FROM
        aws_eks_cluster
    WHERE
        (version)::decimal < 1.19;
    EOT
} 

#

query "iam_policy_custom_attached_no_star_star" {
  title = "3.41 IAM policies should not allow full '*' administrative privileges"
  sql = <<EOT
    WITH star_access_policies AS (
        SELECT
            arn,
            COUNT(*) AS num_bad_statements
        FROM
            aws_iam_policy,
            JSONB_ARRAY_ELEMENTS(policy_std -> 'Statement') AS s,
            JSONB_ARRAY_ELEMENTS_TEXT(s -> 'Resource') AS resource,
            JSONB_ARRAY_ELEMENTS_TEXT(s -> 'Action') AS action
        WHERE
            NOT is_aws_managed
            AND s ->> 'Effect' = 'Allow'
            AND resource = '*'
            AND (
                action = '*'
                OR action = '*:*'
            )
            AND is_attached
        GROUP BY
            arn
    )
    SELECT
        p.name AS resource,
        'alarm' AS status,
        p.name || ' contains ' || COALESCE(s.num_bad_statements, 0) || ' statements that allow action "*" on resource "*".' AS reason,
        p.account_id
    FROM
        aws_iam_policy AS p
    LEFT JOIN
        star_access_policies AS s ON p.arn = s.arn
    WHERE
        NOT p.is_aws_managed
        AND s.arn IS NOT NULL;

    EOT
}

# 

query "iam_root_user_no_access_keys" {
  title = "3.42 IAM root user access key should not exist"
  sql = <<EOT
    SELECT
        'arn:' || partition || ':::' || account_id AS resource,
        'alarm' AS status,
        'Root user access keys exist.' AS reason,
        account_id
    FROM
        aws_iam_account_summary
    WHERE
        account_access_keys_present > 0;

    EOT
}

#

query "kms_key_not_pending_deletion" {
  title = "3.43 AWS KMS keys should not be unintentionally deleted "
  sql = <<EOT
    SELECT
        arn AS resource,
        'alarm' AS status,
        title || ' scheduled for deletion and will be deleted in ' || extract(
            day
            FROM
                deletion_date - current_timestamp
            ) || ' day(s).' AS reason,
        region,
        account_id
    FROM
        aws_kms_key
    WHERE
        key_manager = 'CUSTOMER'
        AND key_state = 'PendingDeletion';
    EOT
}


#

query "opensearch_domain_in_vpc" {
  title = "3.44 OpenSearch domains should be in a VPC"
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

query "opensearch_domain_fine_grained_access_enabled" {
  title = "3.45 OpenSearch domains should have fine-grained access query enabled"
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
        or not (advanced_security_options -> 'Enabled') :: boolean then title || ' has fine-grained access query disabled.'
        else title || ' has fine-grained access query enabled.'
    end as reason,
    region,
    account_id
    from
    aws_opensearch_domain;
    EOT
}



#

query "rds_db_snapshot_prohibit_public_access" {
  title = "3.46 RDS snapshots should be private"
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

query "ssm_managed_instance_compliance_patch_compliant" {
  title = "3.47 All EC2 instances managed by Systems Manager should be compliant with patching requirements"
  sql = <<EOT
    SELECT
        id AS resource,
        'alarm' AS status,
        c.resource_id || ' patch ' || c.title || ' is non-compliant.' AS reason,
        c.region,
        c.account_id
    FROM
        aws_ssm_managed_instance AS i
    JOIN
        aws_ssm_managed_instance_compliance AS c ON c.resource_id = i.instance_id
    WHERE
        c.compliance_type = 'Patch'
        AND c.status != 'COMPLIANT'
        AND c.status != '';
    EOT
}

#

query "autoscaling_launch_config_requires_imdsv2" {
  title = "3.48 Auto Scaling group should configure EC2 instances to require Instance Metadata Service Version 2 (IMDSv2)"
  sql = <<EOT
    SELECT
        name AS resource,
        'alarm' AS status,
        title || ' not configured to use Instance Metadata Service Version 2 (IMDSv2).' AS reason,
        region,
        account_id
    FROM
        aws_ec2_launch_configuration
    WHERE
        metadata_options_http_tokens != 'required'
        OR metadata_options_http_tokens IS NULL;
    EOT
}