# OctoPrint PSU Control - Tapo
Adds Tapo Smart Plug support to OctoPrint-PSUControl as a sub-plugin

## Supported Devices
- **Single socket plugs**: P100, P110, L510, L520, L530, L900, L920
- **Power strips**: P300, P115 (automatic socket discovery)

## Setup
1. Install the plugin using Plugin Manager from Settings
2. Configure this plugin with your Tapo credentials
3. Select this plugin as a Switching and/or Sensing method in [PSU Control](https://github.com/kantlivelong/OctoPrint-PSUControl)

## Configuration

### Single Socket Devices (P100, P110, etc.)
Simply enter your device details:
- **Address**: IP address or hostname of your Tapo device
- **Username**: Your Tapo account email
- **Password**: Your Tapo account password

### Power Strips (P300, P115)
For power strips with multiple sockets, you need to select which socket to control.

#### Prerequisites
1. **Enable Third Party Services** in the Tapo app:
   - Open Tapo app (on the same network as the device)
   - Go to Device → Settings (⚙️) → Third Party Services → Enable

#### Selecting a Socket
1. Enter your device **Address**, **Username**, and **Password**
2. **Save** your settings
3. Click the **"Find Sockets"** button
4. A dropdown will appear showing all available sockets with their names (as configured in the Tapo app)
5. Select the socket you want to control from the dropdown
6. The settings are saved automatically when you select a socket

## Troubleshooting

### "Find Sockets" button doesn't find any sockets
- Make sure **Third Party Services** is enabled in the Tapo app
- Verify that the device and OctoPrint are on the same network/VLAN
- Check that the Address, Username, and Password are correct
- Make sure you have **saved** your settings before clicking "Find Sockets"

### Error 1003 or authentication failures on P300
- Make sure **Third Party Services** is enabled in the Tapo app
- The device and OctoPrint must be on the same network/VLAN

### Connection timeout
- Verify the IP address is correct
- Check that the device is powered on and connected to WiFi

## Support
Help can be found at the [OctoPrint Community Forums](https://community.octoprint.org)

## Support
Help can be found at the [OctoPrint Community Forums](https://community.octoprint.org)
