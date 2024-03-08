dashboard "report" {

  title         = "0. Ops Team AWS Review Accounts"

  tags = merge(local.aws_common_tags, {
    type     = "Report"
    category = "Ops Team"
  })


  container {
    container {
    width = 8
      image {
        src = "https://ops.team/wp-content/uploads/2023/06/logo2-1.png"
        alt = "Ops Team Logo"
        width = 2
      }      
    }    
  }

  container {

    card {
      query = query.account_count
      width = 2
    }
  }    

  table {
    column "ARN" {
      display = "none"
    }

    query = query.account_table
  }  


  benchmark "opsteam" {
    title = " "

    children = [
        benchmark.compliance,
        benchmark.cost,
        benchmark.security
    ]
  }
  
}

benchmark "compliance" {
  title = "1. Compliance"
  description   = "Compiance findigs"
  children = [
   control.vpc_default_security_group_restricts_all_traffic,
   control.iam_user_access_key_age_90,
   control.iam_account_password_policy_strong_min_length_8,
   control.iam_root_user_hardware_mfa_enabled,
   control.rds_db_instance_in_backup_plan,
   control.rds_db_instance_backup_enabled,
   control.dynamodb_table_point_in_time_recovery_enabled,
   control.dynamodb_table_in_backup_plan,
   control.cloudtrail_multi_region_trail_enabled,
   control.cloudtrail_trail_enabled,
   control.ec2_ebs_default_encryption_enabled,
   control.vpc_network_acl_unused,
   control.vpc_security_group_associated_to_eni,
   control.cloudtrail_trail_logs_encrypted_with_kms_cmk,
   control.cloudtrail_trail_validation_enabled,
   control.eks_cluster_no_default_vpc,
   control.eks_cluster_no_multiple_security_groups,
   control.elb_application_lb_redirect_http_request_to_https,
   control.kms_key_decryption_restricted_in_iam_customer_managed_policy,
   control.lambda_function_use_latest_runtime,
   control.sns_topic_encrypted_at_rest,
   control.sqs_queue_encrypted_at_rest
  ] 
}

benchmark "cost" {
  title = "2. Cost"
  description   = "Cost findings"
  children = [
    control.full_month_cost_changes,
    control.vpc_eip_associated,
    control.ebs_volume_unused,
    control.ec2_stopped_instance_30_days,
    control.rds_mysql_version,
    control.gp2_volumes,
    control.ec2_instance_with_graviton,
    control.rds_db_instance_with_graviton
  ] 
}

benchmark "security" {
  title = "3. Security"
  description   = "Security findings"
  children = [
    control.vpc_security_group_allows_ingress_to_cassandra_ports,
    control.vpc_security_group_allows_ingress_to_memcached_port,
    control.vpc_security_group_allows_ingress_to_mongodb_ports,
    control.vpc_security_group_allows_ingress_to_oracle_ports,
    control.vpc_security_group_restrict_ingress_kafka_port,
    control.vpc_security_group_restrict_ingress_redis_port,
    control.vpc_security_group_restrict_ingress_ssh_all,
    control.vpc_security_group_restrict_ingress_rdp_all,
    control.vpc_security_group_restrict_ingress_tcp_udp_all,
    control.autoscaling_ec2_launch_configuration_no_sensitive_data,
    control.cloudformation_stack_output_no_secrets,
    control.ecs_task_definition_container_environment_no_secret,
    control.ec2_instance_no_launch_wizard_security_group,
    control.iam_policy_no_star_star,
    control.rds_db_instance_prohibit_public_access,
    control.s3_bucket_policy_restricts_cross_account_permission_changes,
    control.s3_bucket_restrict_public_read_access,
    control.s3_bucket_restrict_public_write_access,
    control.s3_public_access_block_bucket_account,
    control.sqs_queue_policy_prohibit_public_access,
    control.sns_topic_policy_prohibit_subscription_access,
    control.ec2_ami_restrict_public_access,
    control.ec2_instance_not_publicly_accessible,
    control.ecr_repository_prohibit_public_access,
    control.vpc_security_group_restricted_common_ports,
    control.iam_role_trust_policy_prohibit_public_access,
    control.cloudtrail_bucket_not_public,
    control.efs_file_system_restrict_public_access,
    control.elb_application_classic_network_lb_prohibit_public_access,
    control.ssm_document_prohibit_public_access,
    control.ebs_attached_volume_encryption_enabled,
    control.kms_cmk_policy_prohibit_public_access,
    control.lambda_function_restrict_public_access,
    control.eks_cluster_endpoint_public_access_restricted,
    control.eks_cluster_secrets_encrypted,
    control.eks_cluster_control_plane_audit_logging_enabled,
    control.cloudfront_distribution_no_non_existent_s3_origin,
    control.ecr_repository_image_scan_on_push_enabled,
    control.ecs_task_definition_container_readonly_root_filesystem,
    control.eks_cluster_with_latest_kubernetes_version,
    control.iam_policy_custom_attached_no_star_star,
    control.iam_root_user_no_access_keys,
    control.kms_key_not_pending_deletion,
    control.opensearch_domain_in_vpc,
    control.opensearch_domain_fine_grained_access_enabled,
    control.rds_db_snapshot_prohibit_public_access,
    control.ssm_managed_instance_compliance_patch_compliant,
    control.autoscaling_launch_config_requires_imdsv2

  ] 
}

