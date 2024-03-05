control "full_month_cost_changes" {
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

control "vpc_eip_associated" {
  title = "2.2 VPC EIPs should be associated with an EC2 instance or ENI"
  sql = <<EOT
    select
    'arn:' || partition || ':ec2:' || region || ':' || account_id || ':eip/' || allocation_id as resource,
    case
        when association_id is null then 'alarm'
        else 'ok'
    end status,
    case
        when association_id is null then title || ' is not associated with any resource.'
        else title || ' is associated with a resource.'
    end reason,
    region,
    account_id
    from
    aws_vpc_eip;
    EOT
}   

#

control "ebs_volume_unused" {
  title = "2.3 EBS volumes should be attached to EC2 instances"
  sql = <<EOT
    select
    arn as resource,
    case
        when state = 'in-use' then 'ok'
        else 'alarm'
    end as status,
    case
        when state = 'in-use' then title || ' attached to EC2 instance.'
        else title || ' not attached to EC2 instance.'
    end as reason,
    region,
    account_id
    from
    aws_ebs_volume;
    EOT
}   

#

control "ec2_stopped_instance_30_days" {
  title = "2.4 EC2 stopped instances should be removed in 30 days"
  sql = <<EOT
    select
    arn as resource,
    case
        when instance_state not in ('stopped', 'stopping') then 'skip'
        when state_transition_time <= (current_date - interval '30' day) then 'alarm'
        else 'ok'
    end as status,
    case
        when instance_state not in ('stopped', 'stopping') then title || ' is in ' || instance_state || ' state.'
        else title || ' stopped since ' || to_char(state_transition_time, 'DD-Mon-YYYY') || ' (' || extract(
        day
        from
            current_timestamp - state_transition_time
        ) || ' days).'
    end as reason,
    region,
    account_id
    from
    aws_ec2_instance;
    EOT
}

control "rds_mysql_version" {
  title = "2.5 RDS running in MySQL version < 8. Additional support cost"
  sql = <<EOT
    SELECT
        db_instance_identifier as resource,
        engine_version,
        region AS region,
        account_id AS account_id,
        CASE
            WHEN SPLIT_PART(engine_version, '.', 1)::INTEGER < 8 THEN 'alarm'
            ELSE 'ok'
        END AS status,
        CASE
            WHEN SPLIT_PART(engine_version, '.', 1)::INTEGER < 8 THEN title || 'running in mysql version < 8'
            ELSE title || ' running in mysql version >= 8'
        END AS reason
    FROM
        aws_rds_db_instance
    WHERE
        engine = 'mysql';
    EOT
}

