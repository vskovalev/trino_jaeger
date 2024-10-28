package trino

import future.keywords.contains
import future.keywords.if
import future.keywords.in

default allow = false

allow if {
	is_admin
}

allow if {
	is_bob
	can_be_accessed_by_bob
}

is_admin if {
	input.context.identity.user == "admin"
}

is_bob if {
	input.context.identity.user == "bob"
}

can_be_accessed_by_bob if {
	input.action.operation in ["ImpersonateUser", "FilterCatalogs"]
}

# ... rest of the policy ...
# this assumes the non-batch response field is called "allow"
batch contains i if {
	some i
	raw_resource := input.action.filterResources[i]
	allow with input.action.resource as raw_resource
}

# Corner case: filtering columns is done with a single table item, and many columns inside
# We cannot use our normal logic in other parts of the policy as they are based on sets
# and we need to retain order
batch contains i if {
	some i
	input.action.operation == "FilterColumns"
	count(input.action.filterResources) == 1
	raw_resource := input.action.filterResources[0]
	count(raw_resource.table.columns) > 0
	new_resources := [
	object.union(raw_resource, {"table": {"column": column_name}}) |
		column_name := raw_resource.table.columns[_]
	]
	allow with input.action.resource as new_resources[i]
}