query "full_month_cost_changes" {
  title = "2.1 What services have changed in cost over last two months?"
  sql = <<EOT
    with base_month as (
    select
        dimension_1 as service_name,
        replace(lower(trim(dimension_1)), ' ', '-') as service,
        partition,
        account_id,
        _ctx,
        net_unblended_cost_unit as unit,
        sum(net_unblended_cost_amount) as cost,
        region
    from
        aws_cost_usage
    where
        granularity = 'MONTHLY'
        and dimension_type_1 = 'SERVICE'
        and dimension_type_2 = 'RECORD_TYPE'
        and dimension_2 not in ('Credit')
        and period_start >= date_trunc('month', current_date - interval '2' month)
        and period_start < date_trunc('month', current_date - interval '1' month)
    group by
        1,
        2,
        3,
        4,
        5,
        unit,
        region
    ),
    prev_month as (
    select
        dimension_1 as service_name,
        replace(lower(trim(dimension_1)), ' ', '-') as service,
        partition,
        account_id,
        _ctx,
        net_unblended_cost_unit as unit,
        sum(net_unblended_cost_amount) as cost,
        region
    from
        aws_cost_usage
    where
        granularity = 'MONTHLY'
        and dimension_type_1 = 'SERVICE'
        and dimension_type_2 = 'RECORD_TYPE'
        and dimension_2 not in ('Credit')
        and period_start >= date_trunc('month', current_date - interval '1' month)
        and period_start < date_trunc('month', current_date)
    group by
        1,
        2,
        3,
        4,
        5,
        unit,
        region
    )
    select
    case
        when prev_month.service_name is null then 'arn:' || base_month.partition || ':::' || base_month.account_id || ':cost/' || base_month.service
        else 'arn:' || prev_month.partition || ':::' || prev_month.account_id || ':cost/' || prev_month.service
    end as resource,
    case
        when base_month.cost is null then 'info'
        when prev_month.cost is null then 'ok' -- adjust this value to change threshold for the alarm
        when (prev_month.cost - base_month.cost) > 10 then 'alarm'
        else 'ok'
    end as status,
    case
        when base_month.cost is null then prev_month.service_name || ' usage is new this month with a spend of ' || round(cast(prev_month.cost as numeric), 2) || ' ' || prev_month.unit
        when prev_month.cost is null then 'No usage billing for ' || base_month.service_name || ' in current month.'
        when abs(prev_month.cost - base_month.cost) < 0.01 then prev_month.service_name || ' has remained flat.'
        when prev_month.cost > base_month.cost then prev_month.service_name || ' usage has increased by ' || round(
        cast((prev_month.cost - base_month.cost) as numeric),
        2
        ) || ' ' || prev_month.unit
        else prev_month.service_name || ' usage has decreased (' || round(
        cast((base_month.cost - prev_month.cost) as numeric),
        2
        ) || ') ' || prev_month.unit
    end as reason,
    prev_month.region,
    prev_month.account_id
    from
    base_month
    full outer join prev_month on base_month.service_name = prev_month.service_name
    where
    prev_month.cost != base_month.cost
    order by
    (prev_month.cost - base_month.cost) desc;
    EOT
}    

#

query "vpc_eip_associated" {
  title = "2.2 VPC EIPs should be associated with an EC2 instance or ENI"
  sql = <<EOT
    select
        'arn:' || partition || ':ec2:' || region || ':' || account_id || ':eip/' || allocation_id as resource,
        'alarm' as status,
        title || ' is not associated with any resource.' as reason,
        region,
        account_id
    from
        aws_vpc_eip
    where
        association_id is null;

    EOT
}   

#

query "ebs_volume_unused" {
  title = "2.3 EBS volumes should be attached to EC2 instances"
  sql = <<EOT
    select
        volume_id as resource,
        'alarm' as status,
        title || ' not attached to EC2 instance.' as reason,
        region,
        account_id
    from
        aws_ebs_volume
    where
        state != 'in-use';

    EOT
}   

#

query "ec2_stopped_instance_30_days" {
  title = "2.4 EC2 stopped instances should be removed in 30 days"
  sql = <<EOT
    select
        instance_id as resource,
        'alarm' as status,
        title || ' stopped since ' || to_char(state_transition_time, 'DD-Mon-YYYY') || ' (' || extract(
        day
        from
            current_timestamp - state_transition_time
        ) || ' days).' as reason,
        region,
        account_id
    from
        aws_ec2_instance
    where
        instance_state = 'stopped'
        and state_transition_time <= (current_date - interval '30' day);
    EOT
}

query "rds_mysql_version" {
  title = "2.5 RDS running in MySQL version < 8. Additional support cost"
  sql = <<EOT
    SELECT
        db_instance_identifier AS resource,
        CASE
            WHEN CAST(SPLIT_PART(engine_version, '.', 1) AS INTEGER) < 8 THEN 'alarm'
            ELSE 'ok'
        END AS status,
        CASE
            WHEN CAST(SPLIT_PART(engine_version, '.', 1) AS INTEGER) < 8 THEN 'MySQL version < 8'
            ELSE 'MySQL version >= 8'
        END AS reason,
        engine_version,
        region,
        account_id     
    FROM
        aws_rds_db_instance
    WHERE
        engine = 'mysql';

    EOT
}

query "gp2_volumes" {
  title = "2.6 Still using gp2 EBS volumes? Should use gp3 instead"
  sql = <<EOT
    SELECT
        volume_id AS resource,
        CASE
            WHEN volume_type = 'gp2' THEN 'alarm'
            WHEN volume_type = 'gp3' THEN 'ok'
            ELSE 'skip'
        END AS status,
        volume_id || ' type is ' || volume_type || '.' AS reason,
        region,
        account_id
    FROM
        aws_ebs_volume
    WHERE
        volume_type = 'gp2';

    EOT
}

query "ec2_instance_with_graviton" {
  title = "2.7 EC2 instances without graviton processor should be reviewed"
  sql = <<EOT
    SELECT
        instance_id AS resource,
        CASE
            WHEN platform = 'windows' THEN 'skip'
            WHEN architecture = 'arm64' THEN 'ok'
            ELSE 'alarm'
        END AS status,
        CASE
            WHEN platform = 'windows' THEN title || ' is a Windows type machine.'
            WHEN architecture = 'arm64' THEN title || ' is using a Graviton processor.'
            ELSE title || ' is not using a Graviton processor.'
        END AS reason,
        region,
        account_id
    FROM
        aws_ec2_instance
    WHERE
        CASE
            WHEN platform = 'windows' THEN 'skip'
            WHEN architecture = 'arm64' THEN 'ok'
            ELSE 'alarm'
        END = 'alarm';

    EOT
}


query "rds_db_instance_with_graviton" {
  title = "2.8 RDS DB instances without graviton processor should be reviewed"
  sql = <<EOT
    SELECT
        db_instance_identifier AS resource,
        CASE
            WHEN class LIKE 'db.%g%.%' THEN 'ok'
            ELSE 'alarm'
        END AS status,
        CASE
            WHEN class LIKE 'db.%g%.%' THEN title || ' is using a Graviton processor.'
            ELSE title || ' is not using a Graviton processor.'
        END AS reason,
        region,
        account_id
    FROM
        aws_rds_db_instance
    WHERE
        CASE
            WHEN class LIKE 'db.%g%.%' THEN 'ok'
            ELSE 'alarm'
        END = 'alarm';

    EOT
}