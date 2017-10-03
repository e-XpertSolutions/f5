# retrieve the ordered list of active APM sessionIDs
catch {set output [exec /usr/bin/sessiondump --allkeys | grep starttime | sort -k3 | cut -c1-8]}

  if {$output != ""} {
    # move the output to a list of sessionID
    set output [split $output "\n"]
    set count [llength $output]

    # determine the max_access_session allowed for the running platform
    set max_access [string trim [lindex [split [exec /usr/bin/tmsh show /sys license detail | grep access] " "] 1] "\[\]"]

    # determine acceptable threshold before triggering
    set access_threshold [expr round($max_access*0.85)]
    set diff [expr $count-$access_threshold]

    # kill oldest APM sessions until reaching 85% of active sessions in the APM device
    for {set i 0} {$i < $diff} {incr i} {
      catch { [exec /usr/bin/sessiondump --delete [lindex $output $i]] }
    }
  }
