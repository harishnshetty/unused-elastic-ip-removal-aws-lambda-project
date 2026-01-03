import boto3
import json
import time

SNS_TOPIC_ARN = 'arn:aws:sns:ap-south-1:970378220457:stale-ebs'
REGION = 'ap-south-1'
DRY_RUN = True # Set to True to test without deleting
NOTIFY_ONLY = True # Set to True to only notify without deleting

cloudwatch = boto3.client('cloudwatch', region_name=REGION)
sns = boto3.client('sns', region_name=REGION)

def get_resource_name_tag(resource):
    """Get the 'Name' tag from a resource"""
    tags = resource.get('Tags', [])
    for tag in tags:
        if tag.get('Key', '').lower() == 'name':
            return tag.get('Value', '')
    return 'N/A'

def format_eip_details(eip, region):
    """Format EIP details for reporting"""
    allocation_id = eip.get('AllocationId', 'N/A')
    public_ip = eip.get('PublicIp', 'N/A')
    instance_id = eip.get('InstanceId', 'Not Associated')
    network_interface_id = eip.get('NetworkInterfaceId', 'Not Associated')
    association_id = eip.get('AssociationId', 'N/A')
    private_ip_address = eip.get('PrivateIpAddress', 'N/A')
    domain = eip.get('Domain', 'vpc')  # 'vpc' or 'standard'
    name_tag = get_resource_name_tag(eip)
    
    status = "UNUSED" if instance_id == 'Not Associated' and network_interface_id == 'Not Associated' else "ASSOCIATED"
    
    return {
        'Region': region,
        'PublicIp': public_ip,
        'AllocationId': allocation_id,
        'NameTag': name_tag,
        'Domain': domain,
        'InstanceId': instance_id,
        'NetworkInterfaceId': network_interface_id,
        'AssociationId': association_id,
        'PrivateIpAddress': private_ip_address,
        'Status': status
    }

def get_instance_name(ec2, instance_id):
    """Get the name of an EC2 instance"""
    if instance_id == 'Not Associated':
        return 'N/A'
    
    try:
        response = ec2.describe_instances(InstanceIds=[instance_id])
        if response['Reservations']:
            instance = response['Reservations'][0]['Instances'][0]
            return get_resource_name_tag(instance)
    except Exception:
        pass
    return 'N/A'

def get_eni_details(ec2, network_interface_id):
    """Get details about a Network Interface"""
    if network_interface_id == 'Not Associated':
        return {'Name': 'N/A', 'Status': 'N/A'}
    
    try:
        response = ec2.describe_network_interfaces(
            NetworkInterfaceIds=[network_interface_id]
        )
        if response['NetworkInterfaces']:
            eni = response['NetworkInterfaces'][0]
            name = get_resource_name_tag(eni)
            status = eni.get('Status', 'N/A')
            return {'Name': name, 'Status': status}
    except Exception:
        pass
    return {'Name': 'N/A', 'Status': 'N/A'}

def delete_eip(ec2, eip_detail):
    """Delete an Elastic IP"""
    try:
        if eip_detail['Domain'] == 'vpc':
            # For VPC EIPs
            response = ec2.release_address(
                AllocationId=eip_detail['AllocationId'],
                DryRun=DRY_RUN
            )
        else:
            # For EC2-Classic EIPs
            response = ec2.release_address(
                PublicIp=eip_detail['PublicIp'],
                DryRun=DRY_RUN
            )
        return True
    except Exception as e:
        if "DryRunOperation" in str(e):
            return True  # Dry run success
        raise e

def lambda_handler(event, context):
    ec2_global = boto3.client('ec2', region_name=REGION)
    regions = [r['RegionName'] for r in ec2_global.describe_regions()['Regions']]

    total_eips_global = 0
    unused_eips_global = 0
    associated_eips_global = 0
    deleted_eips_global = 0
    
    all_eip_details = []
    unused_eip_details = []
    associated_eip_details = []
    deleted_eip_details = []
    deletion_errors = []

    widgets = []

    for region in regions:
        try:
            ec2 = boto3.client('ec2', region_name=region)
            cloudwatch = boto3.client('cloudwatch', region_name=region)

            # Get all Elastic IPs
            all_eips = ec2.describe_addresses()
            eip_count = len(all_eips['Addresses'])
            total_eips_global += eip_count
            
            # Process each EIP
            region_unused_eips = []
            region_associated_eips = []
            
            for eip in all_eips['Addresses']:
                eip_detail = format_eip_details(eip, region)
                all_eip_details.append(eip_detail)
                
                # Get additional details for associated resources
                if eip_detail['InstanceId'] != 'Not Associated':
                    instance_name = get_instance_name(ec2, eip_detail['InstanceId'])
                    eip_detail['InstanceName'] = instance_name
                    eip_detail['AssociatedResource'] = f"Instance: {eip_detail['InstanceId']} ({instance_name})"
                    region_associated_eips.append(eip_detail)
                    associated_eip_details.append(eip_detail)
                    associated_eips_global += 1
                    
                elif eip_detail['NetworkInterfaceId'] != 'Not Associated':
                    eni_details = get_eni_details(ec2, eip_detail['NetworkInterfaceId'])
                    eip_detail['ENIName'] = eni_details['Name']
                    eip_detail['ENIStatus'] = eni_details['Status']
                    eip_detail['AssociatedResource'] = f"ENI: {eip_detail['NetworkInterfaceId']} ({eni_details['Name']})"
                    region_associated_eips.append(eip_detail)
                    associated_eip_details.append(eip_detail)
                    associated_eips_global += 1
                    
                else:
                    eip_detail['AssociatedResource'] = 'Unattached'
                    region_unused_eips.append(eip_detail)
                    unused_eip_details.append(eip_detail)
                    unused_eips_global += 1
            
            # Delete unused EIPs if enabled
            region_deleted_eips = []
            if not NOTIFY_ONLY and region_unused_eips:
                for eip_detail in region_unused_eips:
                    try:
                        if delete_eip(ec2, eip_detail):
                            deletion_status = "DRY_RUN" if DRY_RUN else "DELETED"
                            eip_detail['DeletionStatus'] = deletion_status
                            eip_detail['DeletionTime'] = time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())
                            region_deleted_eips.append(eip_detail)
                            deleted_eip_details.append(eip_detail)
                            deleted_eips_global += 1
                            print(f"{deletion_status}: EIP {eip_detail['PublicIp']} in {region}")
                    except Exception as e:
                        error_msg = f"Error deleting EIP {eip_detail['PublicIp']} in {region}: {str(e)}"
                        print(error_msg)
                        deletion_errors.append({
                            'Region': region,
                            'PublicIp': eip_detail['PublicIp'],
                            'Error': str(e)
                        })
            
            # Publish CloudWatch metrics
            timestamp = time.time()
            cloudwatch.put_metric_data(
                Namespace='Custom/EIPMetrics',
                MetricData=[
                    {
                        'MetricName': 'TotalEIPCount',
                        'Dimensions': [{'Name': 'Region', 'Value': region}],
                        'Value': eip_count,
                        'Unit': 'Count',
                        'Timestamp': timestamp
                    },
                    {
                        'MetricName': 'UnusedEIPCount',
                        'Dimensions': [{'Name': 'Region', 'Value': region}],
                        'Value': len(region_unused_eips),
                        'Unit': 'Count',
                        'Timestamp': timestamp
                    },
                    {
                        'MetricName': 'AssociatedEIPCount',
                        'Dimensions': [{'Name': 'Region', 'Value': region}],
                        'Value': len(region_associated_eips),
                        'Unit': 'Count',
                        'Timestamp': timestamp
                    },
                    {
                        'MetricName': 'DeletedEIPCount',
                        'Dimensions': [{'Name': 'Region', 'Value': region}],
                        'Value': len(region_deleted_eips),
                        'Unit': 'Count',
                        'Timestamp': timestamp
                    }
                ]
            )
            
        except Exception as e:
            print(f"Error processing region {region}: {str(e)}")

    # Create Dashboard Widgets
    # Summary widgets
    widgets.append({
        "type": "metric",
        "x": 0,
        "y": 0,
        "width": 3,
        "height": 6,
        "properties": {
            "metrics": [["Custom/EIPMetrics", "TotalEIPCount", {"stat": "Sum"}]],
            "view": "singleValue",
            "stat": "Sum",
            "region": REGION,
            "title": "Total EIPs",
            "period": 300
        }
    })
    
    widgets.append({
        "type": "metric",
        "x": 3,
        "y": 0,
        "width": 3,
        "height": 6,
        "properties": {
            "metrics": [["Custom/EIPMetrics", "AssociatedEIPCount", {"stat": "Sum"}]],
            "view": "singleValue",
            "stat": "Sum",
            "region": REGION,
            "title": "Associated EIPs",
            "period": 300
        }
    })
    
    widgets.append({
        "type": "metric",
        "x": 6,
        "y": 0,
        "width": 3,
        "height": 6,
        "properties": {
            "metrics": [["Custom/EIPMetrics", "UnusedEIPCount", {"stat": "Sum"}]],
            "view": "singleValue",
            "stat": "Sum",
            "region": REGION,
            "title": "Unused EIPs",
            "period": 300
        }
    })
    
    widgets.append({
        "type": "metric",
        "x": 9,
        "y": 0,
        "width": 3,
        "height": 6,
        "properties": {
            "metrics": [["Custom/EIPMetrics", "DeletedEIPCount", {"stat": "Sum"}]],
            "view": "singleValue",
            "stat": "Sum",
            "region": REGION,
            "title": "Deleted EIPs",
            "period": 300
        }
    })

    # Format tables for dashboard
    def format_eip_table(eip_list, title, show_status=True):
        if not eip_list:
            return f"### {title}\nNo data found.\n"
        
        table = f"### {title}\n\n"
        if show_status:
            table += "| Region | Public IP | Name Tag | Status | Associated Resource |\n"
            table += "|--------|-----------|----------|--------|---------------------|\n"
        else:
            table += "| Region | Public IP | Allocation ID | Name Tag | Domain |\n"
            table += "|--------|-----------|---------------|----------|--------|\n"
        
        for eip in eip_list:
            region = eip['Region']
            public_ip = eip['PublicIp']
            name_tag = eip['NameTag'] if eip['NameTag'] != 'N/A' else '-'
            
            if show_status:
                status = eip['Status']
                associated_resource = eip.get('AssociatedResource', 'N/A')
                table += f"| {region} | {public_ip} | {name_tag} | {status} | {associated_resource} |\n"
            else:
                allocation_id = eip['AllocationId']
                domain = eip['Domain']
                deletion_status = eip.get('DeletionStatus', '')
                if deletion_status:
                    public_ip = f"{public_ip} ({deletion_status})"
                table += f"| {region} | {public_ip} | {allocation_id} | {name_tag} | {domain} |\n"
        
        return table

    # Create comprehensive dashboard report
    dashboard_report = ""
    
    # Associated EIPs
    dashboard_report += format_eip_table(associated_eip_details, "Associated Elastic IPs (In Use)", show_status=True)
    dashboard_report += "\n\n"
    
    # Unused EIPs
    unused_for_display = [eip for eip in unused_eip_details if eip not in deleted_eip_details]
    dashboard_report += format_eip_table(unused_for_display, "Unused Elastic IPs (Not Deleted)", show_status=False)
    dashboard_report += "\n\n"
    
    # Deleted EIPs
    dashboard_report += format_eip_table(deleted_eip_details, f"Deleted Elastic IPs ({'DRY RUN' if DRY_RUN else 'ACTUAL'})", show_status=False)
    
    # Errors if any
    if deletion_errors:
        dashboard_report += "\n### Deletion Errors\n\n"
        dashboard_report += "| Region | Public IP | Error |\n"
        dashboard_report += "|--------|-----------|-------|\n"
        for error in deletion_errors:
            dashboard_report += f"| {error['Region']} | {error['PublicIp']} | {error['Error']} |\n"

    widgets.append({
        "type": "text",
        "x": 0,
        "y": 6,
        "width": 12,
        "height": 18,
        "properties": {
            "markdown": dashboard_report
        }
    })
    
    # Publish dashboard
    dashboard_body = json.dumps({"widgets": widgets})
    cloudwatch.put_dashboard(
        DashboardName="EIP-Management-Dashboard",
        DashboardBody=dashboard_body
    )
    
    # Send SNS notification
    email_body = f"""AWS Elastic IP Management Report
Generated: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}

EXECUTION MODE:
- Dry Run: {'YES' if DRY_RUN else 'NO'}
- Deletion Enabled: {'NO (Notification Only)' if NOTIFY_ONLY else 'YES'}

{'='*70}

SUMMARY:
Total Elastic IPs across all regions: {total_eips_global}
Associated EIPs (In Use): {associated_eips_global}
Unused EIPs Found: {unused_eips_global}
EIPs Deleted: {deleted_eips_global} ({'DRY RUN' if DRY_RUN else 'ACTUAL'})

{'='*70}

ASSOCIATED ELASTIC IPs (In Use):
"""
    
    if associated_eip_details:
        email_body += "\nRegion | Public IP | Name Tag | Associated To | Resource Name\n"
        email_body += "-------|-----------|----------|---------------|---------------\n"
        for eip in associated_eip_details:
            region = eip['Region']
            public_ip = eip['PublicIp']
            name_tag = eip['NameTag'] if eip['NameTag'] != 'N/A' else '-'
            resource_type = "Instance" if eip['InstanceId'] != 'Not Associated' else "ENI"
            resource_id = eip['InstanceId'] if eip['InstanceId'] != 'Not Associated' else eip['NetworkInterfaceId']
            resource_name = eip.get('InstanceName', eip.get('ENIName', '-'))
            
            email_body += f"{region} | {public_ip} | {name_tag} | {resource_type}: {resource_id} | {resource_name}\n"
    else:
        email_body += "No associated Elastic IPs found.\n"
    
    email_body += f"\n{'='*70}\n"
    email_body += "\nUNUSED ELASTIC IPs (Remaining - Not Deleted):\n"
    
    # Show only unused EIPs that were not deleted
    remaining_unused = [eip for eip in unused_eip_details if eip not in deleted_eip_details]
    if remaining_unused:
        email_body += "\nRegion | Public IP | Allocation ID | Name Tag | Domain\n"
        email_body += "-------|-----------|---------------|----------|-------\n"
        for eip in remaining_unused:
            email_body += f"{eip['Region']} | {eip['PublicIp']} | {eip['AllocationId']} | {eip['NameTag']} | {eip['Domain']}\n"
    else:
        email_body += "No unused Elastic IPs remaining. All unused EIPs have been processed.\n"
    
    email_body += f"\n{'='*70}\n"
    email_body += f"\nDELETED ELASTIC IPs ({'DRY RUN' if DRY_RUN else 'ACTUAL DELETION'}):\n"
    
    if deleted_eip_details:
        email_body += "\nRegion | Public IP | Allocation ID | Name Tag | Domain | Deletion Time\n"
        email_body += "-------|-----------|---------------|----------|--------|---------------\n"
        for eip in deleted_eip_details:
            email_body += f"{eip['Region']} | {eip['PublicIp']} | {eip['AllocationId']} | {eip['NameTag']} | {eip['Domain']} | {eip.get('DeletionTime', 'N/A')}\n"
    else:
        email_body += f"No Elastic IPs were deleted.\n"
    
    if deletion_errors:
        email_body += f"\n{'='*70}\n"
        email_body += "\nDELETION ERRORS:\n"
        email_body += "\nRegion | Public IP | Error\n"
        email_body += "-------|-----------|-------\n"
        for error in deletion_errors:
            email_body += f"{error['Region']} | {error['PublicIp']} | {error['Error']}\n"
    
    email_body += f"\n{'='*70}\n"
    email_body += "\nNOTES:\n"
    email_body += "1. Unassociated Elastic IPs incur hourly charges\n"
    email_body += "2. Regular cleanup of unused EIPs is recommended to optimize costs\n"
    email_body += "3. Check the CloudWatch dashboard for detailed information\n"

    subject_prefix = "[DRY RUN] " if DRY_RUN else ""
    subject_prefix += "[NOTIFY ONLY] " if NOTIFY_ONLY else ""
    
    sns.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject=f"{subject_prefix}AWS EIP Management - {associated_eips_global} Associated, {unused_eips_global} Unused, {deleted_eips_global} Deleted",
        Message=email_body
    )
    
    return {
        'statusCode': 200,
        'body': json.dumps({
            'message': 'EIP management completed',
            'total_eips': total_eips_global,
            'associated_eips': associated_eips_global,
            'unused_eips': unused_eips_global,
            'deleted_eips': deleted_eips_global,
            'dry_run': DRY_RUN,
            'deletion_enabled': not NOTIFY_ONLY,
            'associated_details': associated_eip_details,
            'unused_details': [eip for eip in unused_eip_details if eip not in deleted_eip_details],
            'deleted_details': deleted_eip_details,
            'errors': deletion_errors
        })
    }