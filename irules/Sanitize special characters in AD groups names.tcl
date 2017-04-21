when ACCESS_POLICY_AGENT_EVENT {
    if { [ACCESS::policy agent_id] eq "clean_group_names" } {
        set newMemberOf " | "
        set memberOf [ACCESS::session data get "session.ad.last.attr.memberOf"]
        set splited [split $memberOf "|"]
        # Loop through all groups
        foreach field $splited {
            # If the group starts with 0x, it is hexa, needs to be decoded
            if { $field starts_with " 0x" } {
                # remove spaces
                set trimed [string trim $field " "] 
                # skip the 0x at the beginning
                set hex_data [string tolower [substr $trimed 2]] 
                # Loop through all items in datagroup
                foreach item [class names dg_special_chars] { 
                    set new_char [class lookup $item dg_special_chars]
                    # Replace the special char with a "normal" char
                    regsub -all $item $hex_data $new_char hex_data
                }
                # Decode the hexa without special chars to string
                set groupStr [binary format H* $hex_data]
                # Concat the sanitize group name to the list
                set newMemberOf [concat $newMemberOf $groupStr " | "]
            # The group is not hexa, just concat the value as it is
            } elseif { $field ne "" } {
                set newMemberOf [concat $newMemberOf $field " | "]
            }
        }
        # Store the sanitize memberOf into a new session var
        ACCESS::session data set "session.custom.ad.memberOf" $newMemberOf
    }
}
