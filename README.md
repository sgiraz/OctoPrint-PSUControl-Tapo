# OctoPrint PSU Control - Tapo
Adds Tapo Smart Plug support to OctoPrint-PSUControl as a sub-plugin

## Supported Devices
- **Single socket plugs**: P100, P110, L510, L520, L530, L900, L920
- **Power strips**: P300, P115 (requires Terminal ID configuration)

## Setup
1. Install the plugin using Plugin Manager from Settings
2. Configure this plugin with your Tapo credentials
3. Select this plugin as a Switching and/or Sensing method in [PSU Control](https://github.com/kantlivelong/OctoPrint-PSUControl)

## Configuration

### Single Socket Devices (P100, P110, etc.)
- **Address**: IP address or hostname of your Tapo device
- **Username**: Your Tapo account email
- **Password**: Your Tapo account password
- **Terminal ID**: Leave empty

### Power Strips (P300, P115)
For power strips with multiple sockets, you need to specify which socket to control using the Terminal ID.

#### Prerequisites
1. **Enable Third Party Services** in the Tapo app:
   - Open Tapo app (on the same network as the device)
   - Go to Device → Settings (⚙️) → Third Party Services → Enable

#### Finding the Terminal ID
Use [python-kasa](https://github.com/python-kasa/python-kasa) to discover the device IDs of each socket:

```bash
pip install python-kasa
```

```python
import asyncio
from kasa import Discover

async def main():
    device = await Discover.discover_single(
        "YOUR_P300_IP",
        username="your_email@example.com",
        password="your_password"
    )
    await device.update()
    
    print(f"Device: {device.model}")
    for child in device.children:
        print(f"  {child.alias}: {child.device_id}")
    
    await device.protocol.close()

asyncio.run(main())
```

This will output something like:
```
Device: P300
  Socket 1: 802233948BDF409BA2D4BE6C9D577B7A249F80AA00
  Socket 2: 802233948BDF409BA2D4BE6C9D577B7A249F80AA01
  Socket 3: 802233948BDF409BA2D4BE6C9D577B7A249F80AA02
```

Copy the full device_id of the socket you want to control and paste it in the **Terminal ID** field.

#### Configuration Example
- **Address**: `192.168.1.18`
- **Username**: `your_email@example.com`
- **Password**: `your_password`
- **Terminal ID**: `802233948BDF409BA2D4BE6C9D577B7A249F80AA00`

## Troubleshooting

### Error 1003 or authentication failures on P300
- Make sure **Third Party Services** is enabled in the Tapo app
- The device and OctoPrint must be on the same network/VLAN

### Connection timeout
- Verify the IP address is correct
- Check that the device is powered on and connected to WiFi

### Terminal ID not working
- Ensure you're using the **full device_id** (not just the suffix)
- Verify the Terminal ID by running the discovery script above

## Support
Help can be found at the [OctoPrint Community Forums](https://community.octoprint.org)
