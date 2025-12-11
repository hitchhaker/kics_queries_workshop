package Cx

import data.generic.common as common_lib

CxPolicy[result] {
	doc := input.document[i]
	resource := doc.resource.aws_security_group[securityGroupName]
	not is_used(securityGroupName, doc, resource)

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_security_group",
		"resourceName": get_resource_name(resource, securityGroupName),
		"searchKey": sprintf("aws_security_group[%s]", [securityGroupName]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("'aws_security_group[%s]' should be used", [securityGroupName]),
		"keyActualValue": sprintf("'aws_security_group[%s]' is not used", [securityGroupName]),
	}
}

is_used(securityGroupName, doc, resource) {
	[path, value] := walk(doc)
	securityGroupUsed := value.security_groups[_]
	contains(securityGroupUsed, sprintf("aws_security_group.%s", [securityGroupName]))
}

# check in modules for module terraform-aws-modules/security-group/aws
is_used(securityGroupName, doc, resource) {
	[path, value] := walk(doc)
	securityGroupUsed := value.security_group_id
	contains(securityGroupUsed, sprintf("aws_security_group.%s", [securityGroupName]))
}

# check security groups assigned to aws_instance resources
is_used(securityGroupName, doc, resource) {
	[path, value] := walk(doc)
    securityGroupUsed := value.vpc_security_group_ids[_]
	contains(securityGroupUsed, sprintf("aws_security_group.%s", [securityGroupName]))
}

# check security groups assigned to aws_eks_cluster resources
is_used(securityGroupName, doc, resource) {
	[path, value] := walk(doc)
	securityGroupUsed := value.vpc_config.security_group_ids[_]
	contains(securityGroupUsed, sprintf("aws_security_group.%s", [securityGroupName]))
}
is_used(securityGroupName, doc, resource) {
	sec_group_used := resource.name
    [path, value] := walk(doc)
	securityGroupUsed := value.security_groups[_]
	sec_group_used == securityGroupUsed
}

############################
# Inlined helpers from terraform.rego and common.rego
# ############################

get_tag_name_if_exists(resource) = name {
	name := resource.tags.Name
} else = name {
	tag := resource.Properties.Tags[_]
	tag.Key == "Name"
	name := tag.Value
} else = name {
	tag := resource.Properties.FileSystemTags[_]
	tag.Key == "Name"
	name := tag.Value
} else = name {
	tag := resource.Properties.Tags[key]
	key == "Name"
	name := tag
} else = name {
	tag := resource.spec.forProvider.tags[_]
	tag.key == "Name"
	name := tag.value
} else = name {
	tag := resource.properties.tags[key]
	key == "Name"
	name := tag
}

get_resource_name(resource, resourceDefinitionName) = name {
	name := resource["name"]
} else = name {
	name := resource["display_name"]
}  else = name {
	name := resource.metadata.name
} else = name {
	prefix := resource.name_prefix
	name := sprintf("%s<unknown-sufix>", [prefix])
} else = name {
	name := get_tag_name_if_exists(resource)
} else = name {
	name := resourceDefinitionName
}
