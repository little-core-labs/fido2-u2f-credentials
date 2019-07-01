const isZeroBuffer = require('is-zero-buffer')
const assert = require('assert')
const crypto = require('../crypto')
const hidraw = require('hidraw-native')
const ioctl = require('ioctl-native')
const util = require('util')
const hid = require('hid')
const fs = require('fs')
const os = require('os')

const isLinux = 'linux' === os.platform()

// derived from https://github.com/Yubico/libu2f-host/blob/master/u2f-host/inc/u2f_hid.h

// The broadcast channel ID
const BROADCAST_CHANNEL_ID = 0xffffffff

// Frame type integer mask
const FRAME_TYPE_MASK = 0x80

// The initial frame ID
const FRAME_TYPE_INIT = 0x80

const FIDO_USAGE_PAGE = 0xf1d0
const FIDO_USAGE_U2FHID = 0x01

const U2F_HID_TIMEOUT = 2
const U2F_HID_MAX_TIMEOUT = 4096

const U2F_HID_PING = (FRAME_TYPE_INIT | 0x01)
const U2F_HID_MSG = (FRAME_TYPE_INIT | 0x03)
const U2F_HID_LOCK = (FRAME_TYPE_INIT | 0x04)
const U2F_HID_INIT = (FRAME_TYPE_INIT | 0x06)
const U2F_HID_WINK = (FRAME_TYPE_INIT | 0x08)
const U2F_HID_ERROR = (FRAME_TYPE_INIT | 0x3f)
const U2F_HID_VENDOR_FIRST = (FRAME_TYPE_INIT | 0x40)
const U2F_HID_VENDOR_LAST = (FRAME_TYPE_INIT | 0x7f)

const U2F_HID_INIT_NONCE_BYTES = 8

const U2F_HID_CAP_FLAG_WINK = 0x01
const U2F_HID_CAP_FLAG_LOCK = 0x02
const U2F_HID_CTAP_KEEPALIVE = (FRAME_TYPE_INIT | 0x3b)

const U2F_HID_FRAME_BYTES = 64

class Devices extends Array {
  find(query) {
    if ('string' === typeof query) {
      query = { path: query }
    }

    const result = super.find((device) => query.path === device.path)

    if (result && result.path !== query.path) {
      return null
    }

    if (!result) {
      return null
    }

    return result
  }

  add(devices) {
    if (!Array.isArray(devices)) {
      devices = [ devices ]
    }

    return this.push(...devices)
  }

  remove(query) {
    const result = this.find(query)
    if (result) {
      const index = this.indexOf(result)
      return this.splice(index, 1)
    }

    return false
  }

  has(query) {
    return null !== this.find(query)
  }

  usage(query) {
    const device = this.find(query)

    if (!device) {
      return null
    }

    let { usage_page, usage } = device

    if (false === isLinux) {
      return { usage, usage_page }
    }

    const size = Buffer.alloc(8)
    const fd = fs.openSync(device.path, fs.constants.O_RDONLY)
    let rc = 0

    if (fd > 0) {
      rc = ioctl(fd, hidraw.HIDIOCGRDESCSIZE, size)
      if (rc >= 0) {
        const report = Buffer.alloc(hidraw.HIDRAW_REPORT_DESCRIPTOR_BYTES)
        const data = report.slice(4)
        const len = size.readUInt32LE(0)

        report.writeUInt32LE(len, 0)
        rc = ioctl(fd, hidraw.HIDIOCGRDESC, report)

        let i = 0
        let missing = 2

        while (i < len) {
          const key = data[i]
          const cmd = key & 0xfc

          assert(0xf0 !== (key & 0xf0), 'Invalid data for key in usage report')

          const sizeCode = key & 0x3

          let dataLength = 0
          let keyLength = 0

          switch (sizeCode) {
            case 0:
            case 1:
            case 2:
              dataLength = sizeCode
              break

            case 3:
              dataLength = 4
              break;

            default:
              dataLength = 0;
          }

          keyLength = 1

          // usage page
          if (0x4 === cmd) {
            usage_page = getBytes(data, len, dataLength, i)
            missing--
          }

          // usage
          if (0x8 == cmd) {
            usage = getBytes(data, len, dataLength, i)
            missing--
          }

          if (0 === missing) {
            break
          }

          i += dataLength + keyLength
        }
      }

      fs.closeSync(fd)

      return { usage, usage_page }
    }

    return null

    function getBytes(data, len, size, index) {
      if (index + size >=  len) {
        return 0
      }

      if (0 === size) {
        return 0
      }

      if (1 === size) {
        return data[index + 1]
      }

      if (2 === size) {
        return data[index + 2] * 256 + data[index +1]
      }

      return 0
    }
  }
}

const Frame = (opts, buffer = Buffer.alloc(U2F_HID_FRAME_BYTES)) =>
  Object.assign({
    get buffer() { return buffer },

    get cid() { return buffer.readUInt32BE(0) },
    set cid(value) { buffer.writeUInt32BE(value, 0) },

    // begin union
    get type() { return buffer.readUInt8(4) },
    set type(value) { buffer.writeUInt8(value, 4) },

    init: {
      get cmd() { return buffer.readUInt8(4) },
      set cmd(value) { buffer.writeUInt8(value, 4) },

      get bcnth() { return buffer.readUInt8(5) },
      set bcnth(value) { buffer.writeUInt8(value, 5) },

      get bcntl() { return buffer.readUInt8(6) },
      set bcntl(value) { buffer.writeUInt8(value, 6) },

      get data() {
        return buffer.slice(7).slice(0, U2F_HID_FRAME_BYTES - 7)
      }
    },

    cont: {
      get seq() { return buffer.readUInt8(4) },
      set seq(value) { buffer.writeUInt8(value, 4) },
      get data() {
        return buffer.slice(5).slice(0, U2F_HID_FRAME_BYTES - 5)
      }
    },

    // end union

    [util.inspect.custom]() {
      return {
        cid: this.cid,
        type: this.type,
        init: {
          cmd: this.init.cmd,
          bcnth: this.init.bcnth,
          bcntl: this.init.bcntl,
          data: this.init.data,
        },

        cont: {
          seq: this.cont.seq,
          data: this.cont.data
        }
      }
    },
  }, opts)

async function enumerate(vendor, product) {
  return new Promise((resolve, reject) => {
    return process.nextTick(ontick, vendor || 0, product || 0)
    function ontick(vid, pid) {
      try {
        const devices = Devices.from(hid.enumerate(vid, pid))
        resolve(devices)
      } catch (err) {
        reject(err)
      }
    }
  })
}

async function discover(devices, vendor, product) {
  const discovered = new Devices()

  if ('number' === typeof devices) {
    product = vendor
    vendor = devices
    devices = new Devices()
  }

  if (false === Array.isArray(devices)) {
    devices = new Devices()
  }

  return new Promise((resolve, reject) => {
    return process.nextTick(ontick)

    async function ontick() {
      try {
        discovered.add(await enumerate(vendor, product))
      } catch (err) {
        // fatal
        return reject(er)
      }

      for (const device of discovered) {
        const report = discovered.usage(device)
        let found = false
        let okay = true

        okay = Boolean(
          report &&
          report.usage === FIDO_USAGE_U2FHID &&
          report.usage_page === FIDO_USAGE_PAGE
        )

        if (okay) {
          device.usage = report.usage
          device.usage_page = report.usage_page

          try {
            const frame = await init(device)
            okay = true
          } catch (err) {
            okay = false
          }
        }

        if (!okay) {
          devices.remove(device)
        } else if (false === devices.has(device)) {
          devices.add(device)
        }
      }

      process.nextTick(resolve, devices)
    }
  })
}

async function ping(device) {
  return sendrecv(device, U2F_HID_PING, Buffer.from([ 0x0 ]))
}

async function init(device) {
  const nonce = crypto.randomBytes(U2F_HID_INIT_NONCE_BYTES)

  device.cid = BROADCAST_CHANNEL_ID

  if ('string' === typeof device.path && device.path.length) {
    device.ref = hid.open_path(device.path)
  } else {
    const { vendor_id, product_id, serial_number } = device
    device.ref = hid.open(vendor_id, product_id, serial_number)
  }

  hid.set_nonblocking(device.ref, 1)

  const response = await sendrecv(device, U2F_HID_INIT, nonce)
  device.cid = response.init.data.slice(nonce.length).readUInt32BE(0)
  return response

}

async function send(device, command, p1, data) {
  const { length } = data
  const message = Buffer.alloc(7 + length)

  message[1] = command
  message[2] = p1
  message[5] = (length >> 8) & 0xff
  message[6] = length & 0xff

  data.copy(message, 7)

  const response = await sendrecv(device, U2F_HID_MSG, message)
  return response
}

async function sendrecv(device, command, data) {
  return new Promise((resolve, reject) => {
    let sent = 0
    let seq = 0

    return send()

    function send() {
      while (data.length > sent) {
        const frame = Frame({ cid: device.cid })
        let len = data.length - sent
        let buf = null
        let max = 0

        if (0 === sent) {
          frame.init.cmd = command
          frame.init.bcnth = (data.length >> 8) & 0xff
          frame.init.bcntl = data.length & 0xff
          buf = frame.init.data
        } else {
          frame.cont.seq = seq++
          buf = frame.cont.data
        }

        max = buf.length

        if (len > max) {
          len = max
        }

        data.copy(buf, 0, sent, len)
        sent += len

        const enc = Buffer.concat([ Buffer.from([0]), frame.buffer ])
        const written = hid.write(device.ref, enc)

        if (written < 0) {
          return reject(new Error('hid.write() failed to write with transport error'))
        }

        if (written !== enc.length) {
          return reject(new Error('hid.write() failed to write packet'))
        }
      }

      return recv()
    }

    function recv() {
      let nread = 0
      let bytes = 0
      let timeout = U2F_HID_TIMEOUT
      let timeoutFactor = 2

      const out = Buffer.alloc(16 * 1024) // 16kb
      const data = Buffer.alloc(U2F_HID_FRAME_BYTES)
      const frame = Frame({ })

      do {
        timeout = U2F_HID_TIMEOUT
        bytes = 0

        while (0 === bytes) {
          bytes = hid.read_timeout(device.ref, data, timeout)
          timeout *= timeoutFactor

          if (timeout > U2F_HID_MAX_TIMEOUT) {
            return reject(new Error('hid.read_timeout() failed to read device'))
          }

          nread += bytes
        }

        data.copy(frame.buffer)
      } while (
        frame.cid === device.cid &&
        frame.init.cmd == U2F_HID_CTAP_KEEPALIVE);

      if (frame.cid !== device.cid || frame.init.cmd !== command) {
        return reject(new Error('Failed to decode response from device'))
      }

      frame.init.data.copy(out)
      nread = frame.init.data.length
      seq = 0

      const len = frame.init.bcnth << 8 | frame.init.bcntl
      let off = frame.init.data.length

      while (len > nread) {
        timeout = U2F_HID_TIMEOUT
        bytes = 0

        while (0 === bytes) {
          bytes = hid.read_timeout(device.ref, data, timeout)
          timeout *= timeoutFactor

          if (timeout > U2F_HID_MAX_TIMEOUT) {
            return reject(new Error('hid.read_timeout() failed to read device'))
          }

        }

        if (bytes > 0) {
          data.copy(frame.buffer)
          nread += frame.cont.data.length
          frame.cont.data.copy(out, off)
          off += frame.cont.data.length
        }

        if (frame.cid !== device.cid || frame.cont.seq !== seq++) {
          return reject(new Error('Failed to decode response from device'))
        }
      }

      if (off < nread) {
        frame.cont.data.copy(out, off)
        off += frame.cont.data.length
      }

      frame.body = out.slice(0, len - 2)
      return resolve(frame)
    }
  })
}

module.exports = {
  enumerate,
  discover,
  ping,
  send,
}
