package device

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	deviceConfig "github.com/lxc/incus/v6/internal/server/device/config"
	"github.com/lxc/incus/v6/internal/server/ip"
	"github.com/lxc/incus/v6/internal/server/state"
	"github.com/lxc/incus/v6/shared/api"
)

// IBDevPrefix Infiniband devices prefix.
const IBDevPrefix = "infiniband.unix"

// infinibandDevices extracts the infiniband parent device from the supplied nic list and any free
// associated virtual functions (VFs) that are on the same card and port as the specified parent.
// This function expects that the supplied nic list does not include VFs that are already attached
// to running instances.
func infinibandDevices(nics *api.ResourcesNetwork, parent string) map[string]*api.ResourcesNetworkCardPort {
	ibDevs := make(map[string]*api.ResourcesNetworkCardPort)
	for _, card := range nics.Cards {
		for _, port := range card.Ports {
			// Skip non-infiniband ports.
			if port.Protocol != "infiniband" {
				continue
			}

			// Skip port if not parent.
			if port.ID != parent {
				continue
			}

			// Store infiniband port info.
			ibDevs[port.ID] = &port
		}

		// Skip virtual function (VF) extraction if SRIOV isn't supported on port.
		if card.SRIOV == nil {
			continue
		}

		// Record if parent has been found as a physical function (PF).
		parentDev, parentIsPF := ibDevs[parent]

		for _, VF := range card.SRIOV.VFs {
			for _, port := range VF.Ports {
				// Skip non-infiniband VFs.
				if port.Protocol != "infiniband" {
					continue
				}

				// Skip VF if parent is a PF and VF is not on same port as parent.
				if parentIsPF && parentDev.Port != port.Port {
					continue
				}

				// Skip VF if parent isn't a PF and VF doesn't match parent name.
				if !parentIsPF && port.ID != parent {
					continue
				}

				// Store infiniband VF port info.
				ibDevs[port.ID] = &port
			}
		}
	}

	return ibDevs
}

// infinibandAddDevices creates the UNIX devices for the provided IBF device and then configures the
// supplied runConfig with the Cgroup rules and mount instructions to pass the device into instance.
func infinibandAddDevices(s *state.State, devicesPath string, deviceName string, ibDev *api.ResourcesNetworkCardPort, runConf *deviceConfig.RunConfig) error {
	if ibDev.Infiniband == nil {
		return fmt.Errorf("No infiniband devices supplied")
	}

	// Add IsSM device if defined.
	if ibDev.Infiniband.IsSMName != "" {
		device := deviceConfig.Device{
			"source": fmt.Sprintf("/dev/infiniband/%s", ibDev.Infiniband.IsSMName),
		}

		err := unixDeviceSetup(s, devicesPath, IBDevPrefix, deviceName, device, false, runConf)
		if err != nil {
			return err
		}
	}

	// Add MAD device if defined.
	if ibDev.Infiniband.MADName != "" {
		device := deviceConfig.Device{
			"source": fmt.Sprintf("/dev/infiniband/%s", ibDev.Infiniband.MADName),
		}

		err := unixDeviceSetup(s, devicesPath, IBDevPrefix, deviceName, device, false, runConf)
		if err != nil {
			return err
		}
	}

	// Add Verb device if defined.
	if ibDev.Infiniband.VerbName != "" {
		device := deviceConfig.Device{
			"source": fmt.Sprintf("/dev/infiniband/%s", ibDev.Infiniband.VerbName),
		}

		err := unixDeviceSetup(s, devicesPath, IBDevPrefix, deviceName, device, false, runConf)
		if err != nil {
			return err
		}
	}

	return nil
}

// infinibandValidMAC validates an infiniband MAC address. Supports both short and long variants,
// e.g. "4a:c8:f9:1b:aa:57:ef:19" and "a0:00:0f:c0:fe:80:00:00:00:00:00:00:4a:c8:f9:1b:aa:57:ef:19".
func infinibandValidMAC(value string) error {
	_, err := net.ParseMAC(value)

	// Check valid lengths and delimiter.
	if err != nil || (len(value) != 23 && len(value) != 59) || strings.ContainsAny(value, "-.") {
		return fmt.Errorf("Invalid value, must be either 8 or 20 bytes of hex separated by colons")
	}

	return nil
}

// infinibandSetDevMAC detects whether the supplied MAC is a short or long form variant.
// If the short form variant is supplied then only the last 8 bytes of the ibDev device's hwaddr
// are changed. If the long form variant is supplied then the full 20 bytes of the ibDev device's
// hwaddr are changed.
func infinibandSetDevMAC(ibDev string, hwaddr string) error {
	// Handle 20 byte variant, e.g. a0:00:14:c0:fe:80:00:00:00:00:00:00:4a:c8:f9:1b:aa:57:ef:19.
	if len(hwaddr) == 59 {
		return NetworkSetDevMAC(ibDev, hwaddr)
	}

	// Handle 8 byte variant, e.g. 4a:c8:f9:1b:aa:57:ef:19.
	if len(hwaddr) == 23 {
		curHwaddr, err := NetworkGetDevMAC(ibDev)
		if err != nil {
			return err
		}

		return NetworkSetDevMAC(ibDev, fmt.Sprintf("%s%s", curHwaddr[:36], hwaddr))
	}

	return fmt.Errorf("Invalid length")
}

// infinibandValidGUID validates an Infiniband GUID (node_guid or port_guid),
// e.g. "4a:c8:f9:1b:aa:57:ef:19".
func infinibandValidGUID(value string) error {
	_, err := net.ParseMAC(value)

	// Check valid length (8 bytes) and delimiter.
	if err != nil || len(value) != 23 || strings.ContainsAny(value, "-.") {
		return fmt.Errorf("Invalid value, must be 8 bytes of hex separated by colons")
	}

	return nil
}

// infinibandSnapshotGUIDs records the port and node guids to volatile so they can be restored later.
func infinibandSnapshotGUIDs(hostName string, vfID int, volatile map[string]string) error {
	// TODO: Check which (if any) of these are necessary
	volatile["last_state.vf.id"] = fmt.Sprintf("%d", vfID)
	// volatile["host_name"] = ???

	nodeGUID, err := infinibandGetVFNodeGUID(hostName, vfID)
	if err != nil {
		return err
	}

	portGUID, err := infinibandGetVFPortGUID(hostName, vfID)
	if err != nil {
		return err
	}

	volatile["last_state.vf.node_guid"] = nodeGUID
	volatile["last_state.vf.port_guid"] = portGUID
	return nil
}

// infinibandRestoreGUIDs restores the port and node guids from volatile to what they were before the device was attached.
func infinibandRestoreGUIDs(hostName string, volatile map[string]string) error {
	// If VF ID is specified, then there might be guids that need restoring.
	if volatile["last_state.vf.id"] != "" {
		vfID, err := strconv.ParseUint(volatile["last_state.vf.id"], 10, 32)
		if err != nil {
			return fmt.Errorf("Failed to convert vfID for \"%s\" vfID \"%s\": %w", hostName, volatile["last_state.vf.id"], err)
		}

		// If node_guid value is specified, then there is an original node_guid that needs restoring.
		if volatile["last_state.vf.node_guid"] != "" {
			err = infinibandSetVFNodeGUID(hostName, int(vfID), volatile["last_state.vf.node_guid"])
			if err != nil {
				return fmt.Errorf("Failed to restore device \"%s\" (VF %d) node_guid to \"%s\": %w", hostName, int(vfID), volatile["last_state.vf.node_guid"], err)
			}
		}

		// If port_guid value is specified, then there is an original port_guid that needs restoring.
		if volatile["last_state.vf.port_guid"] != "" {
			err = infinibandSetVFPortGUID(hostName, int(vfID), volatile["last_state.vf.port_guid"])
			if err != nil {
				return fmt.Errorf("Failed to restore device \"%s\" (VF %d) port_guid to \"%s\": %w", hostName, int(vfID), volatile["last_state.vf.port_guid"], err)
			}
		}
	}

	return nil
}

// infinibandGetVFNodeGUID retrieves the current node_guid setting for an Infiniband VF.
func infinibandGetVFNodeGUID(ibDev string, vfID int) (string, error) {
	// TODO: This is probably wrong as it uses MLNX_OFED (double check with Stephane)
	content, err := os.ReadFile(fmt.Sprintf("/sys/class/infiniband/%s/device/sriov/%d/node", ibDev, vfID))
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(content)), nil
}

// infinibandSetVFNodeGUID sets the node_guid setting for an Infiniband VF if different from current.
func infinibandSetVFNodeGUID(ibDev string, vfID int, nodeGUID string) error {
	curGUID, err := infinibandGetVFNodeGUID(ibDev, vfID)
	if err != nil {
		return err
	}

	// Only try and change the node_guid if the requested node_guid is different to current one.
	if curGUID != nodeGUID {
		guid, err := net.ParseMAC(nodeGUID)
		if err != nil {
			return fmt.Errorf("Failed parsing node_guid %q: %w", nodeGUID, err)
		}

		link := &ip.Link{Name: ibDev}
		err = link.SetNodeGUID(guid, vfID)
		if err != nil {
			return err
		}
	}

	return nil
}

// infinibandGetVFPortGUID retrieves the current port_guid setting for an Infiniband VF.
func infinibandGetVFPortGUID(ibDev string, vfID int) (string, error) {
	// TODO: This is probably wrong as it uses MLNX_OFED (double check with Stephane)
	content, err := os.ReadFile(fmt.Sprintf("/sys/class/infiniband/%s/device/sriov/%d/port", ibDev, vfID))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(content)), nil
}

// infinibandSetVFPortGUID sets the port_guid setting for an Infiniband VF if different from current.
func infinibandSetVFPortGUID(ibDev string, vfID int, portGUID string) error {
	curGUID, err := infinibandGetVFPortGUID(ibDev, vfID)
	if err != nil {
		return err
	}

	// Only try and change the port_guid if the requested port_guid is different to current one.
	if curGUID != portGUID {
		guid, err := net.ParseMAC(portGUID)
		if err != nil {
			return fmt.Errorf("Failed parsing port_guid %q: %w", portGUID, err)
		}

		link := &ip.Link{Name: ibDev}
		err = link.SetPortGUID(guid, vfID)
		if err != nil {
			return err
		}
	}

	return nil
}
