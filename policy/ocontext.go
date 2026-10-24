package policy

// Object context, genfscon and type_attr_map readers (the tail of the file).
//
// Binary kernel policies do not store initial SID names; they are looked up
// in the fixed tables below, indexed by the SID value, exactly as libsepol
// and the reference tools do.

// selinuxSidNames holds the SELinux initial SID names by SID value.
var selinuxSidNames = [...]string{
	"undefined", "kernel", "security", "unlabeled", "fs", "file", "file_labels",
	"init", "any_socket", "port", "netif", "netmsg", "node", "igmp_packet", "icmp_socket",
	"tcp_socket", "sysctl_modprobe", "sysctl", "sysctl_fs", "sysctl_kernel", "sysctl_net",
	"sysctl_net_unix", "sysctl_vm", "sysctl_dev", "kmod", "policy", "scmp_packet", "devnull",
}

// xenSidNames holds the Xen initial SID names by SID value.
var xenSidNames = [...]string{
	"xen", "dom0", "domxen", "domio", "unlabeled", "security", "irq", "iomem", "ioport",
	"device", "domU", "domDM",
}

func selinuxSidName(sid uint32) string {
	if int(sid) < len(selinuxSidNames) {
		return selinuxSidNames[sid]
	}
	return ""
}

func xenSidName(sid uint32) string {
	if int(sid) < len(xenSidNames) {
		return xenSidNames[sid]
	}
	return ""
}

func readOContexts(r *reader, oconNum int) OContexts {
	var o OContexts
	for i := range oconNum {
		nel := r.count(4, "ocontext")
		if r.err != nil {
			return o
		}
		for range nel {
			switch i {
			case OConISid:
				sid := r.u32()
				o.ISids = append(o.ISids, ISidContext{
					SID:     sid,
					Name:    selinuxSidName(sid),
					Context: readContext(r),
				})
			case OConFS, OConNetif:
				nc := NameContext{
					Name:     r.str(),
					Context:  readContext(r),
					Context2: readContext(r),
				}
				if i == OConFS {
					o.FS = append(o.FS, nc)
				} else {
					o.Netifs = append(o.Netifs, nc)
				}
			case OConPort:
				o.Ports = append(o.Ports, PortContext{
					Protocol: r.u32(),
					LowPort:  uint16(r.u32()),
					HighPort: uint16(r.u32()),
					Context:  readContext(r),
				})
			case OConNode:
				var nc NodeContext
				copy(nc.Addr[:], r.bytes(4))
				copy(nc.Mask[:], r.bytes(4))
				nc.Context = readContext(r)
				o.Nodes = append(o.Nodes, nc)
			case OConFSUse:
				fc := FSUseContext{
					Behavior: r.u32(),
					FSType:   r.str(),
					Context:  readContext(r),
				}
				o.FSUse = append(o.FSUse, fc)
			case OConNode6:
				var nc Node6Context
				copy(nc.Addr[:], r.bytes(16))
				copy(nc.Mask[:], r.bytes(16))
				nc.Context = readContext(r)
				o.Nodes6 = append(o.Nodes6, nc)
			case OConIBPkey:
				var pc IBPkeyContext
				copy(pc.SubnetPrefix[:], r.bytes(8))
				pc.LowPKey = uint16(r.u32())
				pc.HighPKey = uint16(r.u32())
				pc.Context = readContext(r)
				o.IBPkeys = append(o.IBPkeys, pc)
			case OConIBEndPort:
				ec := IBEndPortContext{}
				nameLen := r.u32()
				ec.Port = uint8(r.u32())
				ec.DeviceName = string(r.bytes(int(nameLen)))
				ec.Context = readContext(r)
				o.IBEndPorts = append(o.IBEndPorts, ec)
			default:
				r.fail("unknown ocontext section %d", i)
				return o
			}
			if r.err != nil {
				return o
			}
		}
	}
	return o
}

// readContext reads a security context. Kernel policies always store the MLS
// range, even when MLS is disabled in the policy configuration.
func readContext(r *reader) Context {
	c := Context{
		User:  r.u32(),
		Role:  r.u32(),
		Type:  r.u32(),
		Range: readRange(r),
	}
	return c
}

func readGenFS(r *reader) []GenFS {
	nel := r.count(8, "genfs")
	if r.err != nil {
		return nil
	}
	out := make([]GenFS, 0, nel)
	for range nel {
		g := GenFS{FSType: r.str()}
		nctx := r.count(12, "genfs context")
		if r.err != nil {
			return out
		}
		for range nctx {
			g.Contexts = append(g.Contexts, GenFSContext{
				Path:    r.str(),
				Class:   r.u32(),
				Context: readContext(r),
			})
			if r.err != nil {
				return out
			}
		}
		out = append(out, g)
	}
	return out
}

// readTypeAttrMap reads the per-type attribute bitmap. The bits are zero based
// type indices, so they are converted to the symbol values used everywhere
// else.
func readTypeAttrMap(r *reader, numTypes int) [][]uint32 {
	out := make([][]uint32, numTypes)
	for i := range numTypes {
		for _, bit := range r.bitmap() {
			out[i] = append(out[i], bit+1)
		}
		if r.err != nil {
			return out
		}
	}
	return out
}

// readXenOContexts reads the object contexts of a xen target policy.
func readXenOContexts(r *reader, oconNum int) XenOContexts {
	var o XenOContexts
	for i := range oconNum {
		nel := r.count(8, "xen ocontext")
		if r.err != nil {
			return o
		}
		for range nel {
			switch i {
			case 0: // OCON_XEN_ISID
				sid := r.u32()
				o.ISids = append(o.ISids, ISidContext{
					SID:     sid,
					Name:    xenSidName(sid),
					Context: readContext(r),
				})
			case 1: // OCON_XEN_PIRQ
				o.Pirqs = append(o.Pirqs, XenPirqContext{
					IRQ:     uint16(r.u32()),
					Context: readContext(r),
				})
			case 2: // OCON_XEN_IOPORT
				o.IOPorts = append(o.IOPorts, XenIOPortContext{
					Low:     r.u32(),
					High:    r.u32(),
					Context: readContext(r),
				})
			case 3: // OCON_XEN_IOMEM
				o.IOMems = append(o.IOMems, XenIOMemContext{
					Low:     r.u64(),
					High:    r.u64(),
					Context: readContext(r),
				})
			case 4: // OCON_XEN_PCIDEVICE
				o.PCIDevices = append(o.PCIDevices, XenPCIDeviceContext{
					Device:  r.u32(),
					Context: readContext(r),
				})
			case 5: // OCON_XEN_DEVICETREE
				o.DeviceTrees = append(o.DeviceTrees, XenDeviceTreeContext{
					Path:    r.str(),
					Context: readContext(r),
				})
			default:
				r.fail("unknown xen ocontext section %d", i)
				return o
			}
			if r.err != nil {
				return o
			}
		}
	}
	return o
}
