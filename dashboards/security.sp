dashboard "security" {

  title         = "3. Security - Ops Team AWS Review Accounts"

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

  container {
    title = "3. Security"

    table {
      title = "3.1 VPC security groups should restrict ingress from 0.0.0.0/0 or ::/0 to cassandra ports 7199 or 9160 or 8888"
      column "ARN" {
        display = "none"
      }

      query = query.vpc_security_group_allows_ingress_to_cassandra_ports
    } 

    table {
      title = "3.2 VPC security groups should restrict ingress from 0.0.0.0/0 or ::/0 to memcached port 11211"
      column "ARN" {
        display = "none"
      }

      query = query.vpc_security_group_allows_ingress_to_memcached_port
    }

    table {
      title = "3.3 VPC security groups should restrict ingress from 0.0.0.0/0 or ::/0 to mongoDB ports 27017 and 27018"
      column "ARN" {
        display = "none"
      }

      query = query.vpc_security_group_allows_ingress_to_mongodb_ports
    }

    table {
      title = "3.4 VPC security groups should restrict ingress from 0.0.0.0/0 or ::/0 to oracle ports 1521 or 2483"
      column "ARN" {
        display = "none"
      }

      query = query.vpc_security_group_allows_ingress_to_oracle_ports
    }

    table {
      title = "3.5 VPC security groups should restrict ingress Kafka port access from 0.0.0.0/0"
      column "ARN" {
        display = "none"
      }

      query = query.vpc_security_group_restrict_ingress_kafka_port
    }

    table {
      title = "3.6 VPC security groups should restrict ingress redis access from 0.0.0.0/0"
      column "ARN" {
        display = "none"
      }

      query = query.vpc_security_group_restrict_ingress_redis_port
    }

    table {
      title = "3.7 VPC security groups should restrict ingress SSH access from 0.0.0.0/0"
      column "ARN" {
        display = "none"
      }

      query = query.vpc_security_group_restrict_ingress_ssh_all
    }

    table {
      title = "3.8 VPC security groups should restrict ingress RDP access from 0.0.0.0/0"
      column "ARN" {
        display = "none"
      }

      query = query.vpc_security_group_restrict_ingress_rdp_all
    }

    table {
      title = "3.9 VPC security groups should restrict ingress TCP and UDP access from 0.0.0.0/0"
      column "ARN" {
        display = "none"
      }

      query = query.vpc_security_group_restrict_ingress_tcp_udp_all
    }

    table {
      title = "3.10 EC2 auto scaling group launch configurations user data should not have any sensitive data"
      column "ARN" {
        display = "none"
      }

      query = query.autoscaling_ec2_launch_configuration_no_sensitive_data
    }

    table {
      title = "3.11 CloudFormation stacks outputs should not have any secrets"
      column "ARN" {
        display = "none"
      }

      query = query.cloudformation_stack_output_no_secrets
    }

    table {
      title = "3.12 ECS task definition containers should not have secrets passed as environment variables"
      column "ARN" {
        display = "none"
      }

      query = query.ecs_task_definition_container_environment_no_secret
    }

    table {
      title = "3.13 EC2 instances should not be attached to 'launch wizard' security groups"
      column "ARN" {
        display = "none"
      }

      query = query.ec2_instance_no_launch_wizard_security_group
    }

    table {
      title = "3.14 IAM policy should not have statements with admin access"
      column "ARN" {
        display = "none"
      }

      query = query.iam_policy_no_star_star
    }

    table {
      title = "3.15 RDS DB instances should prohibit public access, determined by the PubliclyAccessible configuration"
      column "ARN" {
        display = "none"
      }

      query = query.rds_db_instance_prohibit_public_access
    }

    table {
      title = "3.16 S3 permissions granted to other AWS accounts in bucket policies should be restricted"
      column "ARN" {
        display = "none"
      }

      query = query.s3_bucket_policy_restricts_cross_account_permission_changes
    }

    table {
      title = "3.17 S3 buckets should prohibit public read access"
      column "ARN" {
        display = "none"
      }

      query = query.s3_bucket_restrict_public_read_access
    }

    table {
      title = "3.18 S3 buckets should prohibit public write access"
      column "ARN" {
        display = "none"
      }

      query = query.s3_bucket_restrict_public_write_access
    }

    table {
      title = "3.19 S3 public access should be blocked at account level"
      column "ARN" {
        display = "none"
      }

      query = query.s3_public_access_block_bucket_account
    }

    table {
      title = "3.20 SQS queue policies should prohibit public access"
      column "ARN" {
        display = "none"
      }

      query = query.sqs_queue_policy_prohibit_public_access
    }

    table {
      title = "3.21 SNS topic policies should prohibit public access"
      column "ARN" {
        display = "none"
      }

      query = query.sns_topic_policy_prohibit_subscription_access
    }


    table {
      title = "3.22 EC2 AMIs should restrict public access"
      column "ARN" {
        display = "none"
      }

      query = query.ec2_ami_restrict_public_access
    }

    table {
      title = "3.23 EC2 instances should not have a public IP address"
      column "ARN" {
        display = "none"
      }

      query = query.ec2_instance_not_publicly_accessible
    }

    table {
      title = "3.24. ECR repositories should prohibit public access"
      column "ARN" {
        display = "none"
      }

      query = query.ecr_repository_prohibit_public_access
    }

    table {
      title = "3.25 Security groups should not allow unrestricted access to ports with high risk"
      column "ARN" {
        display = "none"
      }

      query = query.vpc_security_group_restricted_common_ports
    }

    table {
      title = "3.26 IAM role trust policies should prohibit public access"
      column "ARN" {
        display = "none"
      }

      query = query.iam_role_trust_policy_prohibit_public_access
    }

    table {
      title = "3.27 Ensure the S3 bucket CloudTrail logs to is not publicly accessible"
      column "ARN" {
        display = "none"
      }

      query = query.cloudtrail_bucket_not_public
    }

    table {
      title = "3.28 EFS file systems should restrict public access"
      column "ARN" {
        display = "none"
      }

      query = query.efs_file_system_restrict_public_access
    }

    table {
      title = "3.29 ELB load balancers should prohibit public access"
      column "ARN" {
        display = "none"
      }

      query = query.elb_application_classic_network_lb_prohibit_public_access
    }

    table {
      title = "3.30 SSM documents should not be public"
      column "ARN" {
        display = "none"
      }

      query = query.ssm_document_prohibit_public_access
    }

    table {
      title = "3.31 Attached EBS volumes should have encryption enabled"
      column "ARN" {
        display = "none"
      }

      query = query.ebs_attached_volume_encryption_enabled
    }

    table {
      title = "3.32 KMS CMK policies should prohibit public access"
      column "ARN" {
        display = "none"
      }

      query = query.kms_cmk_policy_prohibit_public_access
    }

    table {
      title = "3.33 Lambda functions should restrict public access"
      column "ARN" {
        display = "none"
      }

      query = query.lambda_function_restrict_public_access
    }

    table {
      title = "3.34 EKS clusters endpoint should restrict public access"
      column "ARN" {
        display = "none"
      }

      query = query.eks_cluster_endpoint_public_access_restricted
    }

    table {
      title = "3.35 EKS clusters should be configured to have kubernetes secrets encrypted using KMS"
      column "ARN" {
        display = "none"
      }

      query = query.eks_cluster_secrets_encrypted
    }


    table {
      title = "3.36 EKS clusters should have control plane audit logging enabled"
      column "ARN" {
        display = "none"
      }

      query = query.eks_cluster_control_plane_audit_logging_enabled
    }

    table {
      title = "3.37 CloudFront distributions should not point to non-existent S3 origins"
      column "ARN" {
        display = "none"
      }

      query = query.cloudfront_distribution_no_non_existent_s3_origin
    }

    table {
      title = "3.38 ECR private repositories should have image scanning configured"
      column "ARN" {
        display = "none"
      }

      query = query.ecr_repository_image_scan_on_push_enabled
    }

    table {
      title = "3.39 ECS containers should be limited to read-only access to root filesystems"
      column "ARN" {
        display = "none"
      }

      query = query.ecs_task_definition_container_readonly_root_filesystem
    }

    table {
      title = "3.40 EKS clusters should run on a supported Kubernetes version"
      column "ARN" {
        display = "none"
      }

      query = query.eks_cluster_with_latest_kubernetes_version
    }

    table {
      title = "3.41 IAM policies should not allow full '*' administrative privileges"
      column "ARN" {
        display = "none"
      }

      query = query.iam_policy_custom_attached_no_star_star
    }

    table {
      title = "3.42 IAM root user access key should not exist"
      column "ARN" {
        display = "none"
      }

      query = query.iam_root_user_no_access_keys
    }

    table {
      title = "3.43 AWS KMS keys should not be unintentionally deleted"
      column "ARN" {
        display = "none"
      }

      query = query.kms_key_not_pending_deletion
    }

    table {
      title = "3.44 OpenSearch domains should be in a VPC"
      column "ARN" {
        display = "none"
      }

      query = query.opensearch_domain_in_vpc
    }

    table {
      title = "3.45 OpenSearch domains should have fine-grained access control enabled"
      column "ARN" {
        display = "none"
      }

      query = query.opensearch_domain_fine_grained_access_enabled
    }

    table {
      title = "3.46 RDS snapshots should be private"
      column "ARN" {
        display = "none"
      }

      query = query.rds_db_snapshot_prohibit_public_access
    }

    table {
      title = "3.47 All EC2 instances managed by Systems Manager should be compliant with patching requirements"
      column "ARN" {
        display = "none"
      }

      query = query.ssm_managed_instance_compliance_patch_compliant
    }

    table {
      title = "3.48 Auto Scaling group should configure EC2 instances to require Instance Metadata Service Version 2 (IMDSv2)"
      column "ARN" {
        display = "none"
      }

      query = query.autoscaling_launch_config_requires_imdsv2
    }


  }

}  