$(function() {
    // PSUControl Tapo - Socket Discovery Script
    console.log("PSUControl Tapo: Script loading...");
    
    // Store children data
    var childrenData = [];
    
    function discoverSockets() {
        console.log("PSUControl Tapo: Discover button clicked");
        
        var $btn = $("#psucontrol_tapo_discover_btn");
        var $status = $("#psucontrol_tapo_discover_status");
        var $socketGroup = $("#psucontrol_tapo_socket_group");
        var $socketSelect = $("#psucontrol_tapo_socket_select");
        var $selectedGroup = $("#psucontrol_tapo_selected_group");
        var $selectedName = $("#psucontrol_tapo_selected_name");
        
        // Get settings from OctoPrint
        OctoPrint.settings.get().done(function(allSettings) {
            console.log("PSUControl Tapo: Got settings", allSettings.plugins.psucontrol_tapo);
            
            var pluginSettings = allSettings.plugins.psucontrol_tapo;
            var address = pluginSettings.address || "";
            var username = pluginSettings.username || "";
            var password = pluginSettings.password || "";
            
            if (!address || !username || !password) {
                $status.removeClass("text-success").addClass("text-error")
                    .text("Please fill in Address, Username and Password, then SAVE settings first.");
                return;
            }
            
            // Show loading state
            $btn.prop("disabled", true).text("Searching...");
            $status.removeClass("text-error text-success").text("");
            $socketGroup.hide();
            $socketSelect.empty().append('<option value="">-- Select a socket --</option>');
            
            console.log("PSUControl Tapo: Calling API with address:", address);
            
            // Call the API
            OctoPrint.simpleApiCommand("psucontrol_tapo", "discover_children", {
                address: address,
                username: username,
                password: password
            }).done(function(response) {
                console.log("PSUControl Tapo: API response", response);
                
                // Reset button state
                $btn.prop("disabled", false).html('<i class="fa fa-search icon-search"></i> Find Sockets');
                
                if (response.success) {
                    if (response.children && response.children.length > 0) {
                        childrenData = response.children;
                        
                        response.children.forEach(function(child) {
                            var status = child.device_on ? "ON" : "OFF";
                            var text = child.nickname + " (Socket " + child.position + ") - " + status;
                            $socketSelect.append('<option value="' + child.device_id + '">' + text + '</option>');
                        });
                        
                        // Pre-select current terminal ID if set
                        var currentTerminalId = pluginSettings.terminalId;
                        if (currentTerminalId) {
                            $socketSelect.val(currentTerminalId);
                        }
                        
                        $socketGroup.show();
                        $status.removeClass("text-error").addClass("text-success")
                            .text("Found " + response.children.length + " socket(s). Select one below.");
                    } else if (response.message) {
                        $status.removeClass("text-error").addClass("text-success").text(response.message);
                    } else {
                        $status.removeClass("text-error").addClass("text-success")
                            .text("No sockets found. This is a single socket device.");
                    }
                } else {
                    $status.removeClass("text-success").addClass("text-error")
                        .text("Error: " + (response.error || "Unknown error"));
                }
            }).fail(function(xhr, status, error) {
                console.error("PSUControl Tapo: API call failed", status, error, xhr.responseText);
                
                // Reset button state
                $btn.prop("disabled", false).html('<i class="fa fa-search icon-search"></i> Find Sockets');
                $status.removeClass("text-success").addClass("text-error")
                    .text("Connection failed: " + (error || "Check settings and try again."));
            });
        }).fail(function() {
            console.error("PSUControl Tapo: Could not read settings");
            $status.removeClass("text-success").addClass("text-error")
                .text("Could not read settings.");
        });
    }
    
    function onSocketSelect() {
        var selectedId = $("#psucontrol_tapo_socket_select").val();
        var $status = $("#psucontrol_tapo_discover_status");
        var $selectedGroup = $("#psucontrol_tapo_selected_group");
        var $selectedName = $("#psucontrol_tapo_selected_name");
        
        console.log("PSUControl Tapo: Socket selected:", selectedId);
        
        if (selectedId) {
            // Update the setting via OctoPrint
            OctoPrint.settings.get().done(function(allSettings) {
                allSettings.plugins.psucontrol_tapo.terminalId = selectedId;
                OctoPrint.settings.save(allSettings).done(function() {
                    var child = childrenData.find(function(c) { return c.device_id === selectedId; });
                    if (child) {
                        $selectedName.text(child.nickname + " (Socket " + child.position + ")");
                        $selectedGroup.show();
                        $status.removeClass("text-error").addClass("text-success")
                            .text("Saved: " + child.nickname);
                    }
                }).fail(function() {
                    $status.removeClass("text-success").addClass("text-error")
                        .text("Failed to save settings.");
                });
            });
        }
    }
    
    // Bind events using delegation
    $(document).on("click", "#psucontrol_tapo_discover_btn", function(e) {
        e.preventDefault();
        discoverSockets();
    });
    
    $(document).on("change", "#psucontrol_tapo_socket_select", function() {
        onSocketSelect();
    });
    
    console.log("PSUControl Tapo: Script loaded successfully");
});
