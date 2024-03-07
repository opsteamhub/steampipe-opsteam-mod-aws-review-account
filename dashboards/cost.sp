dashboard "cost" {

  title         = "2. Cost - Ops Team AWS Review Accounts"

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
    title = "2. Cost"

    table {
      title = "2.1 What services have changed in cost over last two months?"
      column "ARN" {
        display = "none"
      }

      query = query.full_month_cost_changes
    }

    table {
      title = "2.2 VPC EIPs should be associated with an EC2 instance or ENI"
      column "ARN" {
        display = "none"
      }

      query = query.vpc_eip_associated
    }

    table {
      title = "2.3 EBS volumes should be attached to EC2 instances"
      column "ARN" {
        display = "none"
      }

      query = query.ebs_volume_unused
    }    

    table {
      title = "2.4 EC2 stopped instances should be removed in 30 days"
      column "ARN" {
        display = "none"
      }

      query = query.ec2_stopped_instance_30_days
    }   

    table {
      title = "2.5 RDS running in MySQL version < 8. Additional support cost"
      column "ARN" {
        display = "none"
      }

      query = query.rds_mysql_version
    } 

  }
}    
