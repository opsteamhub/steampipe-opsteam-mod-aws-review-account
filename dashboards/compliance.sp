dashboard "compliance" {

  title         = "1. Compliance - Ops Team AWS Review Accounts"

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
    title = "1. Compliance"
  

    table {
      title = "1.1 VPC default security group should not allow inbound and outbound traffic"
      column "ARN" {
        display = "none"
      }

      query = query.vpc_default_security_group_restricts_all_traffic
    }
    

    table {
      title = "1.2 IAM user access keys should be rotated at least every 90 days"
      column "ARN" {
        display = "none"
      }

      query = query.iam_user_access_key_age_90
    }

    table {
      title = "1.3 IAM users should have strong configurations with minimum length of 8"
      column "ARN" {
        display = "none"
      }

      query = query.iam_account_password_policy_strong_min_length_8
    }

    table {
      title = "1.4 IAM root user hardware MFA should be enabled"
      column "ARN" {
        display = "none"
      }

      query = query.iam_root_user_hardware_mfa_enabled
    }  
  
    table {
      title = "1.5 RDS DB instances should be in a backup plan"
      column "ARN" {
        display = "none"
      }

      query = query.rds_db_instance_in_backup_plan
    }  

    table {
      title = "1.6 RDS DB instance backup should be enabled"
      column "ARN" {
        display = "none"
      }

      query = query.rds_db_instance_backup_enabled
    }  

    table {
      title = "1.7 DynamoDB table point-in-time recovery should be enabled"
      column "ARN" {
        display = "none"
      }

      query = query.dynamodb_table_point_in_time_recovery_enabled
    }  

    table {
      title = "1.8 DynamoDB tables should be in a backup plan"
      column "ARN" {
        display = "none"
      }

      query = query.dynamodb_table_in_backup_plan
    }  

    table {
      title = "1.9 At least one multi-region AWS CloudTrail should be present in an account"
      column "ARN" {
        display = "none"
      }

      query = query.cloudtrail_multi_region_trail_enabled
    }  

    table {
      title = "1.10 At least one enabled trail should be present in a region"
      column "ARN" {
        display = "none"
      }

      query = query.cloudtrail_trail_enabled
    }  

    table {
      title = "1.11 EBS default encryption should be enabled"
      column "ARN" {
        display = "none"
      }

      query = query.ec2_ebs_default_encryption_enabled
    } 

    table {
      title = "1.12 VPC network access control lists (network ACLs) should be associated with a subnet"
      column "ARN" {
        display = "none"
      }

      query = query.vpc_network_acl_unused
    } 

    table {
      title = "1.13 VPC security groups should be associated with at least one ENI"
      column "ARN" {
        display = "none"
      }

      query = query.vpc_security_group_associated_to_eni
    } 

    table {
      title = "1.14 CloudTrail trail logs should be encrypted with KMS CMK"
      column "ARN" {
        display = "none"
      }

      query = query.cloudtrail_trail_logs_encrypted_with_kms_cmk
    } 

    table {
      title = "1.15 CloudTrail trail log file validation should be enabled"
      column "ARN" {
        display = "none"
      }

      query = query.cloudtrail_trail_validation_enabled
    } 

    table {
      title = "1.16 EKS clusters should not be configured within a default VPC"
      column "ARN" {
        display = "none"
      }

      query = query.eks_cluster_no_default_vpc
    } 

    table {
      title = "1.17 EKS clusters should not use multiple security groups"
      column "ARN" {
        display = "none"
      }

      query = query.eks_cluster_no_multiple_security_groups
    } 
    
    table {
      title = "1.18 Application Load Balancer should be configured to redirect all HTTP requests to HTTPS"
      column "ARN" {
        display = "none"
      }

      query = query.elb_application_lb_redirect_http_request_to_https
    }     


    table {
      title = "1.19 IAM customer managed policies should not allow decryption actions on all KMS keys"
      column "ARN" {
        display = "none"
      }

      query = query.kms_key_decryption_restricted_in_iam_customer_managed_policy
    }     

    table {
      title = "1.20 Lambda functions should use latest runtimes"
      column "ARN" {
        display = "none"
      }

      query = query.lambda_function_use_latest_runtime
    } 

    table {
      title = "1.21 SNS topics should be encrypted at rest using AWS KMS"
      column "ARN" {
        display = "none"
      }

      query = query.sns_topic_encrypted_at_rest
    } 

    table {
      title = "1.22 Amazon SQS queues should be encrypted at rest"
      column "ARN" {
        display = "none"
      }

      query = query.sqs_queue_encrypted_at_rest
    } 
    



  } 
  
}

