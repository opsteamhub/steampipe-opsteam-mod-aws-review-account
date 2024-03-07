locals {
  aws_common_tags = {
    service = "AWS"
  }
}

mod "local" {
  title = "AWS Ops Team Report"


  opengraph {
    title       = "Steampipe Mod for AWS Insights"
    description = "Create dashboards and reports for your AWS resources using Steampipe."
    image       = "/images/mods/turbot/aws-insights-social-graphic.png"
  }

}



