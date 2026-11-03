var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __commonJS = (cb, mod) => function __require() {
  return mod || (0, cb[__getOwnPropNames(cb)[0]])((mod = { exports: {} }).exports, mod), mod.exports;
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));

// node_modules/qrcode/lib/can-promise.js
var require_can_promise = __commonJS({
  "node_modules/qrcode/lib/can-promise.js"(exports, module) {
    module.exports = function() {
      return typeof Promise === "function" && Promise.prototype && Promise.prototype.then;
    };
  }
});

// node_modules/qrcode/lib/core/utils.js
var require_utils = __commonJS({
  "node_modules/qrcode/lib/core/utils.js"(exports) {
    var toSJISFunction;
    var CODEWORDS_COUNT = [
      0,
      // Not used
      26,
      44,
      70,
      100,
      134,
      172,
      196,
      242,
      292,
      346,
      404,
      466,
      532,
      581,
      655,
      733,
      815,
      901,
      991,
      1085,
      1156,
      1258,
      1364,
      1474,
      1588,
      1706,
      1828,
      1921,
      2051,
      2185,
      2323,
      2465,
      2611,
      2761,
      2876,
      3034,
      3196,
      3362,
      3532,
      3706
    ];
    exports.getSymbolSize = function getSymbolSize(version) {
      if (!version) throw new Error('"version" cannot be null or undefined');
      if (version < 1 || version > 40) throw new Error('"version" should be in range from 1 to 40');
      return version * 4 + 17;
    };
    exports.getSymbolTotalCodewords = function getSymbolTotalCodewords(version) {
      return CODEWORDS_COUNT[version];
    };
    exports.getBCHDigit = function(data) {
      let digit = 0;
      while (data !== 0) {
        digit++;
        data >>>= 1;
      }
      return digit;
    };
    exports.setToSJISFunction = function setToSJISFunction(f) {
      if (typeof f !== "function") {
        throw new Error('"toSJISFunc" is not a valid function.');
      }
      toSJISFunction = f;
    };
    exports.isKanjiModeEnabled = function() {
      return typeof toSJISFunction !== "undefined";
    };
    exports.toSJIS = function toSJIS(kanji) {
      return toSJISFunction(kanji);
    };
  }
});

// node_modules/qrcode/lib/core/error-correction-level.js
var require_error_correction_level = __commonJS({
  "node_modules/qrcode/lib/core/error-correction-level.js"(exports) {
    exports.L = { bit: 1 };
    exports.M = { bit: 0 };
    exports.Q = { bit: 3 };
    exports.H = { bit: 2 };
    function fromString(string) {
      if (typeof string !== "string") {
        throw new Error("Param is not a string");
      }
      const lcStr = string.toLowerCase();
      switch (lcStr) {
        case "l":
        case "low":
          return exports.L;
        case "m":
        case "medium":
          return exports.M;
        case "q":
        case "quartile":
          return exports.Q;
        case "h":
        case "high":
          return exports.H;
        default:
          throw new Error("Unknown EC Level: " + string);
      }
    }
    exports.isValid = function isValid(level) {
      return level && typeof level.bit !== "undefined" && level.bit >= 0 && level.bit < 4;
    };
    exports.from = function from(value, defaultValue) {
      if (exports.isValid(value)) {
        return value;
      }
      try {
        return fromString(value);
      } catch (e) {
        return defaultValue;
      }
    };
  }
});

// node_modules/qrcode/lib/core/bit-buffer.js
var require_bit_buffer = __commonJS({
  "node_modules/qrcode/lib/core/bit-buffer.js"(exports, module) {
    function BitBuffer() {
      this.buffer = [];
      this.length = 0;
    }
    BitBuffer.prototype = {
      get: function(index) {
        const bufIndex = Math.floor(index / 8);
        return (this.buffer[bufIndex] >>> 7 - index % 8 & 1) === 1;
      },
      put: function(num, length) {
        for (let i = 0; i < length; i++) {
          this.putBit((num >>> length - i - 1 & 1) === 1);
        }
      },
      getLengthInBits: function() {
        return this.length;
      },
      putBit: function(bit) {
        const bufIndex = Math.floor(this.length / 8);
        if (this.buffer.length <= bufIndex) {
          this.buffer.push(0);
        }
        if (bit) {
          this.buffer[bufIndex] |= 128 >>> this.length % 8;
        }
        this.length++;
      }
    };
    module.exports = BitBuffer;
  }
});

// node_modules/qrcode/lib/core/bit-matrix.js
var require_bit_matrix = __commonJS({
  "node_modules/qrcode/lib/core/bit-matrix.js"(exports, module) {
    function BitMatrix(size) {
      if (!size || size < 1) {
        throw new Error("BitMatrix size must be defined and greater than 0");
      }
      this.size = size;
      this.data = new Uint8Array(size * size);
      this.reservedBit = new Uint8Array(size * size);
    }
    BitMatrix.prototype.set = function(row, col, value, reserved) {
      const index = row * this.size + col;
      this.data[index] = value;
      if (reserved) this.reservedBit[index] = true;
    };
    BitMatrix.prototype.get = function(row, col) {
      return this.data[row * this.size + col];
    };
    BitMatrix.prototype.xor = function(row, col, value) {
      this.data[row * this.size + col] ^= value;
    };
    BitMatrix.prototype.isReserved = function(row, col) {
      return this.reservedBit[row * this.size + col];
    };
    module.exports = BitMatrix;
  }
});

// node_modules/qrcode/lib/core/alignment-pattern.js
var require_alignment_pattern = __commonJS({
  "node_modules/qrcode/lib/core/alignment-pattern.js"(exports) {
    var getSymbolSize = require_utils().getSymbolSize;
    exports.getRowColCoords = function getRowColCoords(version) {
      if (version === 1) return [];
      const posCount = Math.floor(version / 7) + 2;
      const size = getSymbolSize(version);
      const intervals = size === 145 ? 26 : Math.ceil((size - 13) / (2 * posCount - 2)) * 2;
      const positions = [size - 7];
      for (let i = 1; i < posCount - 1; i++) {
        positions[i] = positions[i - 1] - intervals;
      }
      positions.push(6);
      return positions.reverse();
    };
    exports.getPositions = function getPositions(version) {
      const coords = [];
      const pos = exports.getRowColCoords(version);
      const posLength = pos.length;
      for (let i = 0; i < posLength; i++) {
        for (let j = 0; j < posLength; j++) {
          if (i === 0 && j === 0 || // top-left
          i === 0 && j === posLength - 1 || // bottom-left
          i === posLength - 1 && j === 0) {
            continue;
          }
          coords.push([pos[i], pos[j]]);
        }
      }
      return coords;
    };
  }
});

// node_modules/qrcode/lib/core/finder-pattern.js
var require_finder_pattern = __commonJS({
  "node_modules/qrcode/lib/core/finder-pattern.js"(exports) {
    var getSymbolSize = require_utils().getSymbolSize;
    var FINDER_PATTERN_SIZE = 7;
    exports.getPositions = function getPositions(version) {
      const size = getSymbolSize(version);
      return [
        // top-left
        [0, 0],
        // top-right
        [size - FINDER_PATTERN_SIZE, 0],
        // bottom-left
        [0, size - FINDER_PATTERN_SIZE]
      ];
    };
  }
});

// node_modules/qrcode/lib/core/mask-pattern.js
var require_mask_pattern = __commonJS({
  "node_modules/qrcode/lib/core/mask-pattern.js"(exports) {
    exports.Patterns = {
      PATTERN000: 0,
      PATTERN001: 1,
      PATTERN010: 2,
      PATTERN011: 3,
      PATTERN100: 4,
      PATTERN101: 5,
      PATTERN110: 6,
      PATTERN111: 7
    };
    var PenaltyScores = {
      N1: 3,
      N2: 3,
      N3: 40,
      N4: 10
    };
    exports.isValid = function isValid(mask) {
      return mask != null && mask !== "" && !isNaN(mask) && mask >= 0 && mask <= 7;
    };
    exports.from = function from(value) {
      return exports.isValid(value) ? parseInt(value, 10) : void 0;
    };
    exports.getPenaltyN1 = function getPenaltyN1(data) {
      const size = data.size;
      let points = 0;
      let sameCountCol = 0;
      let sameCountRow = 0;
      let lastCol = null;
      let lastRow = null;
      for (let row = 0; row < size; row++) {
        sameCountCol = sameCountRow = 0;
        lastCol = lastRow = null;
        for (let col = 0; col < size; col++) {
          let module2 = data.get(row, col);
          if (module2 === lastCol) {
            sameCountCol++;
          } else {
            if (sameCountCol >= 5) points += PenaltyScores.N1 + (sameCountCol - 5);
            lastCol = module2;
            sameCountCol = 1;
          }
          module2 = data.get(col, row);
          if (module2 === lastRow) {
            sameCountRow++;
          } else {
            if (sameCountRow >= 5) points += PenaltyScores.N1 + (sameCountRow - 5);
            lastRow = module2;
            sameCountRow = 1;
          }
        }
        if (sameCountCol >= 5) points += PenaltyScores.N1 + (sameCountCol - 5);
        if (sameCountRow >= 5) points += PenaltyScores.N1 + (sameCountRow - 5);
      }
      return points;
    };
    exports.getPenaltyN2 = function getPenaltyN2(data) {
      const size = data.size;
      let points = 0;
      for (let row = 0; row < size - 1; row++) {
        for (let col = 0; col < size - 1; col++) {
          const last = data.get(row, col) + data.get(row, col + 1) + data.get(row + 1, col) + data.get(row + 1, col + 1);
          if (last === 4 || last === 0) points++;
        }
      }
      return points * PenaltyScores.N2;
    };
    exports.getPenaltyN3 = function getPenaltyN3(data) {
      const size = data.size;
      let points = 0;
      let bitsCol = 0;
      let bitsRow = 0;
      for (let row = 0; row < size; row++) {
        bitsCol = bitsRow = 0;
        for (let col = 0; col < size; col++) {
          bitsCol = bitsCol << 1 & 2047 | data.get(row, col);
          if (col >= 10 && (bitsCol === 1488 || bitsCol === 93)) points++;
          bitsRow = bitsRow << 1 & 2047 | data.get(col, row);
          if (col >= 10 && (bitsRow === 1488 || bitsRow === 93)) points++;
        }
      }
      return points * PenaltyScores.N3;
    };
    exports.getPenaltyN4 = function getPenaltyN4(data) {
      let darkCount = 0;
      const modulesCount = data.data.length;
      for (let i = 0; i < modulesCount; i++) darkCount += data.data[i];
      const k = Math.abs(Math.ceil(darkCount * 100 / modulesCount / 5) - 10);
      return k * PenaltyScores.N4;
    };
    function getMaskAt(maskPattern, i, j) {
      switch (maskPattern) {
        case exports.Patterns.PATTERN000:
          return (i + j) % 2 === 0;
        case exports.Patterns.PATTERN001:
          return i % 2 === 0;
        case exports.Patterns.PATTERN010:
          return j % 3 === 0;
        case exports.Patterns.PATTERN011:
          return (i + j) % 3 === 0;
        case exports.Patterns.PATTERN100:
          return (Math.floor(i / 2) + Math.floor(j / 3)) % 2 === 0;
        case exports.Patterns.PATTERN101:
          return i * j % 2 + i * j % 3 === 0;
        case exports.Patterns.PATTERN110:
          return (i * j % 2 + i * j % 3) % 2 === 0;
        case exports.Patterns.PATTERN111:
          return (i * j % 3 + (i + j) % 2) % 2 === 0;
        default:
          throw new Error("bad maskPattern:" + maskPattern);
      }
    }
    exports.applyMask = function applyMask(pattern, data) {
      const size = data.size;
      for (let col = 0; col < size; col++) {
        for (let row = 0; row < size; row++) {
          if (data.isReserved(row, col)) continue;
          data.xor(row, col, getMaskAt(pattern, row, col));
        }
      }
    };
    exports.getBestMask = function getBestMask(data, setupFormatFunc) {
      const numPatterns = Object.keys(exports.Patterns).length;
      let bestPattern = 0;
      let lowerPenalty = Infinity;
      for (let p = 0; p < numPatterns; p++) {
        setupFormatFunc(p);
        exports.applyMask(p, data);
        const penalty = exports.getPenaltyN1(data) + exports.getPenaltyN2(data) + exports.getPenaltyN3(data) + exports.getPenaltyN4(data);
        exports.applyMask(p, data);
        if (penalty < lowerPenalty) {
          lowerPenalty = penalty;
          bestPattern = p;
        }
      }
      return bestPattern;
    };
  }
});

// node_modules/qrcode/lib/core/error-correction-code.js
var require_error_correction_code = __commonJS({
  "node_modules/qrcode/lib/core/error-correction-code.js"(exports) {
    var ECLevel = require_error_correction_level();
    var EC_BLOCKS_TABLE = [
      // L  M  Q  H
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      2,
      2,
      1,
      2,
      2,
      4,
      1,
      2,
      4,
      4,
      2,
      4,
      4,
      4,
      2,
      4,
      6,
      5,
      2,
      4,
      6,
      6,
      2,
      5,
      8,
      8,
      4,
      5,
      8,
      8,
      4,
      5,
      8,
      11,
      4,
      8,
      10,
      11,
      4,
      9,
      12,
      16,
      4,
      9,
      16,
      16,
      6,
      10,
      12,
      18,
      6,
      10,
      17,
      16,
      6,
      11,
      16,
      19,
      6,
      13,
      18,
      21,
      7,
      14,
      21,
      25,
      8,
      16,
      20,
      25,
      8,
      17,
      23,
      25,
      9,
      17,
      23,
      34,
      9,
      18,
      25,
      30,
      10,
      20,
      27,
      32,
      12,
      21,
      29,
      35,
      12,
      23,
      34,
      37,
      12,
      25,
      34,
      40,
      13,
      26,
      35,
      42,
      14,
      28,
      38,
      45,
      15,
      29,
      40,
      48,
      16,
      31,
      43,
      51,
      17,
      33,
      45,
      54,
      18,
      35,
      48,
      57,
      19,
      37,
      51,
      60,
      19,
      38,
      53,
      63,
      20,
      40,
      56,
      66,
      21,
      43,
      59,
      70,
      22,
      45,
      62,
      74,
      24,
      47,
      65,
      77,
      25,
      49,
      68,
      81
    ];
    var EC_CODEWORDS_TABLE = [
      // L  M  Q  H
      7,
      10,
      13,
      17,
      10,
      16,
      22,
      28,
      15,
      26,
      36,
      44,
      20,
      36,
      52,
      64,
      26,
      48,
      72,
      88,
      36,
      64,
      96,
      112,
      40,
      72,
      108,
      130,
      48,
      88,
      132,
      156,
      60,
      110,
      160,
      192,
      72,
      130,
      192,
      224,
      80,
      150,
      224,
      264,
      96,
      176,
      260,
      308,
      104,
      198,
      288,
      352,
      120,
      216,
      320,
      384,
      132,
      240,
      360,
      432,
      144,
      280,
      408,
      480,
      168,
      308,
      448,
      532,
      180,
      338,
      504,
      588,
      196,
      364,
      546,
      650,
      224,
      416,
      600,
      700,
      224,
      442,
      644,
      750,
      252,
      476,
      690,
      816,
      270,
      504,
      750,
      900,
      300,
      560,
      810,
      960,
      312,
      588,
      870,
      1050,
      336,
      644,
      952,
      1110,
      360,
      700,
      1020,
      1200,
      390,
      728,
      1050,
      1260,
      420,
      784,
      1140,
      1350,
      450,
      812,
      1200,
      1440,
      480,
      868,
      1290,
      1530,
      510,
      924,
      1350,
      1620,
      540,
      980,
      1440,
      1710,
      570,
      1036,
      1530,
      1800,
      570,
      1064,
      1590,
      1890,
      600,
      1120,
      1680,
      1980,
      630,
      1204,
      1770,
      2100,
      660,
      1260,
      1860,
      2220,
      720,
      1316,
      1950,
      2310,
      750,
      1372,
      2040,
      2430
    ];
    exports.getBlocksCount = function getBlocksCount(version, errorCorrectionLevel) {
      switch (errorCorrectionLevel) {
        case ECLevel.L:
          return EC_BLOCKS_TABLE[(version - 1) * 4 + 0];
        case ECLevel.M:
          return EC_BLOCKS_TABLE[(version - 1) * 4 + 1];
        case ECLevel.Q:
          return EC_BLOCKS_TABLE[(version - 1) * 4 + 2];
        case ECLevel.H:
          return EC_BLOCKS_TABLE[(version - 1) * 4 + 3];
        default:
          return void 0;
      }
    };
    exports.getTotalCodewordsCount = function getTotalCodewordsCount(version, errorCorrectionLevel) {
      switch (errorCorrectionLevel) {
        case ECLevel.L:
          return EC_CODEWORDS_TABLE[(version - 1) * 4 + 0];
        case ECLevel.M:
          return EC_CODEWORDS_TABLE[(version - 1) * 4 + 1];
        case ECLevel.Q:
          return EC_CODEWORDS_TABLE[(version - 1) * 4 + 2];
        case ECLevel.H:
          return EC_CODEWORDS_TABLE[(version - 1) * 4 + 3];
        default:
          return void 0;
      }
    };
  }
});

// node_modules/qrcode/lib/core/galois-field.js
var require_galois_field = __commonJS({
  "node_modules/qrcode/lib/core/galois-field.js"(exports) {
    var EXP_TABLE = new Uint8Array(512);
    var LOG_TABLE = new Uint8Array(256);
    (function initTables() {
      let x = 1;
      for (let i = 0; i < 255; i++) {
        EXP_TABLE[i] = x;
        LOG_TABLE[x] = i;
        x <<= 1;
        if (x & 256) {
          x ^= 285;
        }
      }
      for (let i = 255; i < 512; i++) {
        EXP_TABLE[i] = EXP_TABLE[i - 255];
      }
    })();
    exports.log = function log(n) {
      if (n < 1) throw new Error("log(" + n + ")");
      return LOG_TABLE[n];
    };
    exports.exp = function exp(n) {
      return EXP_TABLE[n];
    };
    exports.mul = function mul(x, y) {
      if (x === 0 || y === 0) return 0;
      return EXP_TABLE[LOG_TABLE[x] + LOG_TABLE[y]];
    };
  }
});

// node_modules/qrcode/lib/core/polynomial.js
var require_polynomial = __commonJS({
  "node_modules/qrcode/lib/core/polynomial.js"(exports) {
    var GF = require_galois_field();
    exports.mul = function mul(p1, p2) {
      const coeff = new Uint8Array(p1.length + p2.length - 1);
      for (let i = 0; i < p1.length; i++) {
        for (let j = 0; j < p2.length; j++) {
          coeff[i + j] ^= GF.mul(p1[i], p2[j]);
        }
      }
      return coeff;
    };
    exports.mod = function mod(divident, divisor) {
      let result = new Uint8Array(divident);
      while (result.length - divisor.length >= 0) {
        const coeff = result[0];
        for (let i = 0; i < divisor.length; i++) {
          result[i] ^= GF.mul(divisor[i], coeff);
        }
        let offset = 0;
        while (offset < result.length && result[offset] === 0) offset++;
        result = result.slice(offset);
      }
      return result;
    };
    exports.generateECPolynomial = function generateECPolynomial(degree) {
      let poly = new Uint8Array([1]);
      for (let i = 0; i < degree; i++) {
        poly = exports.mul(poly, new Uint8Array([1, GF.exp(i)]));
      }
      return poly;
    };
  }
});

// node_modules/qrcode/lib/core/reed-solomon-encoder.js
var require_reed_solomon_encoder = __commonJS({
  "node_modules/qrcode/lib/core/reed-solomon-encoder.js"(exports, module) {
    var Polynomial = require_polynomial();
    function ReedSolomonEncoder(degree) {
      this.genPoly = void 0;
      this.degree = degree;
      if (this.degree) this.initialize(this.degree);
    }
    ReedSolomonEncoder.prototype.initialize = function initialize2(degree) {
      this.degree = degree;
      this.genPoly = Polynomial.generateECPolynomial(this.degree);
    };
    ReedSolomonEncoder.prototype.encode = function encode(data) {
      if (!this.genPoly) {
        throw new Error("Encoder not initialized");
      }
      const paddedData = new Uint8Array(data.length + this.degree);
      paddedData.set(data);
      const remainder = Polynomial.mod(paddedData, this.genPoly);
      const start = this.degree - remainder.length;
      if (start > 0) {
        const buff = new Uint8Array(this.degree);
        buff.set(remainder, start);
        return buff;
      }
      return remainder;
    };
    module.exports = ReedSolomonEncoder;
  }
});

// node_modules/qrcode/lib/core/version-check.js
var require_version_check = __commonJS({
  "node_modules/qrcode/lib/core/version-check.js"(exports) {
    exports.isValid = function isValid(version) {
      return !isNaN(version) && version >= 1 && version <= 40;
    };
  }
});

// node_modules/qrcode/lib/core/regex.js
var require_regex = __commonJS({
  "node_modules/qrcode/lib/core/regex.js"(exports) {
    var numeric = "[0-9]+";
    var alphanumeric = "[A-Z $%*+\\-./:]+";
    var kanji = "(?:[u3000-u303F]|[u3040-u309F]|[u30A0-u30FF]|[uFF00-uFFEF]|[u4E00-u9FAF]|[u2605-u2606]|[u2190-u2195]|u203B|[u2010u2015u2018u2019u2025u2026u201Cu201Du2225u2260]|[u0391-u0451]|[u00A7u00A8u00B1u00B4u00D7u00F7])+";
    kanji = kanji.replace(/u/g, "\\u");
    var byte = "(?:(?![A-Z0-9 $%*+\\-./:]|" + kanji + ")(?:.|[\r\n]))+";
    exports.KANJI = new RegExp(kanji, "g");
    exports.BYTE_KANJI = new RegExp("[^A-Z0-9 $%*+\\-./:]+", "g");
    exports.BYTE = new RegExp(byte, "g");
    exports.NUMERIC = new RegExp(numeric, "g");
    exports.ALPHANUMERIC = new RegExp(alphanumeric, "g");
    var TEST_KANJI = new RegExp("^" + kanji + "$");
    var TEST_NUMERIC = new RegExp("^" + numeric + "$");
    var TEST_ALPHANUMERIC = new RegExp("^[A-Z0-9 $%*+\\-./:]+$");
    exports.testKanji = function testKanji(str) {
      return TEST_KANJI.test(str);
    };
    exports.testNumeric = function testNumeric(str) {
      return TEST_NUMERIC.test(str);
    };
    exports.testAlphanumeric = function testAlphanumeric(str) {
      return TEST_ALPHANUMERIC.test(str);
    };
  }
});

// node_modules/qrcode/lib/core/mode.js
var require_mode = __commonJS({
  "node_modules/qrcode/lib/core/mode.js"(exports) {
    var VersionCheck = require_version_check();
    var Regex = require_regex();
    exports.NUMERIC = {
      id: "Numeric",
      bit: 1 << 0,
      ccBits: [10, 12, 14]
    };
    exports.ALPHANUMERIC = {
      id: "Alphanumeric",
      bit: 1 << 1,
      ccBits: [9, 11, 13]
    };
    exports.BYTE = {
      id: "Byte",
      bit: 1 << 2,
      ccBits: [8, 16, 16]
    };
    exports.KANJI = {
      id: "Kanji",
      bit: 1 << 3,
      ccBits: [8, 10, 12]
    };
    exports.MIXED = {
      bit: -1
    };
    exports.getCharCountIndicator = function getCharCountIndicator(mode, version) {
      if (!mode.ccBits) throw new Error("Invalid mode: " + mode);
      if (!VersionCheck.isValid(version)) {
        throw new Error("Invalid version: " + version);
      }
      if (version >= 1 && version < 10) return mode.ccBits[0];
      else if (version < 27) return mode.ccBits[1];
      return mode.ccBits[2];
    };
    exports.getBestModeForData = function getBestModeForData(dataStr) {
      if (Regex.testNumeric(dataStr)) return exports.NUMERIC;
      else if (Regex.testAlphanumeric(dataStr)) return exports.ALPHANUMERIC;
      else if (Regex.testKanji(dataStr)) return exports.KANJI;
      else return exports.BYTE;
    };
    exports.toString = function toString(mode) {
      if (mode && mode.id) return mode.id;
      throw new Error("Invalid mode");
    };
    exports.isValid = function isValid(mode) {
      return mode && mode.bit && mode.ccBits;
    };
    function fromString(string) {
      if (typeof string !== "string") {
        throw new Error("Param is not a string");
      }
      const lcStr = string.toLowerCase();
      switch (lcStr) {
        case "numeric":
          return exports.NUMERIC;
        case "alphanumeric":
          return exports.ALPHANUMERIC;
        case "kanji":
          return exports.KANJI;
        case "byte":
          return exports.BYTE;
        default:
          throw new Error("Unknown mode: " + string);
      }
    }
    exports.from = function from(value, defaultValue) {
      if (exports.isValid(value)) {
        return value;
      }
      try {
        return fromString(value);
      } catch (e) {
        return defaultValue;
      }
    };
  }
});

// node_modules/qrcode/lib/core/version.js
var require_version = __commonJS({
  "node_modules/qrcode/lib/core/version.js"(exports) {
    var Utils = require_utils();
    var ECCode = require_error_correction_code();
    var ECLevel = require_error_correction_level();
    var Mode = require_mode();
    var VersionCheck = require_version_check();
    var G18 = 1 << 12 | 1 << 11 | 1 << 10 | 1 << 9 | 1 << 8 | 1 << 5 | 1 << 2 | 1 << 0;
    var G18_BCH = Utils.getBCHDigit(G18);
    function getBestVersionForDataLength(mode, length, errorCorrectionLevel) {
      for (let currentVersion = 1; currentVersion <= 40; currentVersion++) {
        if (length <= exports.getCapacity(currentVersion, errorCorrectionLevel, mode)) {
          return currentVersion;
        }
      }
      return void 0;
    }
    function getReservedBitsCount(mode, version) {
      return Mode.getCharCountIndicator(mode, version) + 4;
    }
    function getTotalBitsFromDataArray(segments, version) {
      let totalBits = 0;
      segments.forEach(function(data) {
        const reservedBits = getReservedBitsCount(data.mode, version);
        totalBits += reservedBits + data.getBitsLength();
      });
      return totalBits;
    }
    function getBestVersionForMixedData(segments, errorCorrectionLevel) {
      for (let currentVersion = 1; currentVersion <= 40; currentVersion++) {
        const length = getTotalBitsFromDataArray(segments, currentVersion);
        if (length <= exports.getCapacity(currentVersion, errorCorrectionLevel, Mode.MIXED)) {
          return currentVersion;
        }
      }
      return void 0;
    }
    exports.from = function from(value, defaultValue) {
      if (VersionCheck.isValid(value)) {
        return parseInt(value, 10);
      }
      return defaultValue;
    };
    exports.getCapacity = function getCapacity(version, errorCorrectionLevel, mode) {
      if (!VersionCheck.isValid(version)) {
        throw new Error("Invalid QR Code version");
      }
      if (typeof mode === "undefined") mode = Mode.BYTE;
      const totalCodewords = Utils.getSymbolTotalCodewords(version);
      const ecTotalCodewords = ECCode.getTotalCodewordsCount(version, errorCorrectionLevel);
      const dataTotalCodewordsBits = (totalCodewords - ecTotalCodewords) * 8;
      if (mode === Mode.MIXED) return dataTotalCodewordsBits;
      const usableBits = dataTotalCodewordsBits - getReservedBitsCount(mode, version);
      switch (mode) {
        case Mode.NUMERIC:
          return Math.floor(usableBits / 10 * 3);
        case Mode.ALPHANUMERIC:
          return Math.floor(usableBits / 11 * 2);
        case Mode.KANJI:
          return Math.floor(usableBits / 13);
        case Mode.BYTE:
        default:
          return Math.floor(usableBits / 8);
      }
    };
    exports.getBestVersionForData = function getBestVersionForData(data, errorCorrectionLevel) {
      let seg;
      const ecl = ECLevel.from(errorCorrectionLevel, ECLevel.M);
      if (Array.isArray(data)) {
        if (data.length > 1) {
          return getBestVersionForMixedData(data, ecl);
        }
        if (data.length === 0) {
          return 1;
        }
        seg = data[0];
      } else {
        seg = data;
      }
      return getBestVersionForDataLength(seg.mode, seg.getLength(), ecl);
    };
    exports.getEncodedBits = function getEncodedBits(version) {
      if (!VersionCheck.isValid(version) || version < 7) {
        throw new Error("Invalid QR Code version");
      }
      let d = version << 12;
      while (Utils.getBCHDigit(d) - G18_BCH >= 0) {
        d ^= G18 << Utils.getBCHDigit(d) - G18_BCH;
      }
      return version << 12 | d;
    };
  }
});

// node_modules/qrcode/lib/core/format-info.js
var require_format_info = __commonJS({
  "node_modules/qrcode/lib/core/format-info.js"(exports) {
    var Utils = require_utils();
    var G15 = 1 << 10 | 1 << 8 | 1 << 5 | 1 << 4 | 1 << 2 | 1 << 1 | 1 << 0;
    var G15_MASK = 1 << 14 | 1 << 12 | 1 << 10 | 1 << 4 | 1 << 1;
    var G15_BCH = Utils.getBCHDigit(G15);
    exports.getEncodedBits = function getEncodedBits(errorCorrectionLevel, mask) {
      const data = errorCorrectionLevel.bit << 3 | mask;
      let d = data << 10;
      while (Utils.getBCHDigit(d) - G15_BCH >= 0) {
        d ^= G15 << Utils.getBCHDigit(d) - G15_BCH;
      }
      return (data << 10 | d) ^ G15_MASK;
    };
  }
});

// node_modules/qrcode/lib/core/numeric-data.js
var require_numeric_data = __commonJS({
  "node_modules/qrcode/lib/core/numeric-data.js"(exports, module) {
    var Mode = require_mode();
    function NumericData(data) {
      this.mode = Mode.NUMERIC;
      this.data = data.toString();
    }
    NumericData.getBitsLength = function getBitsLength(length) {
      return 10 * Math.floor(length / 3) + (length % 3 ? length % 3 * 3 + 1 : 0);
    };
    NumericData.prototype.getLength = function getLength() {
      return this.data.length;
    };
    NumericData.prototype.getBitsLength = function getBitsLength() {
      return NumericData.getBitsLength(this.data.length);
    };
    NumericData.prototype.write = function write(bitBuffer) {
      let i, group, value;
      for (i = 0; i + 3 <= this.data.length; i += 3) {
        group = this.data.substr(i, 3);
        value = parseInt(group, 10);
        bitBuffer.put(value, 10);
      }
      const remainingNum = this.data.length - i;
      if (remainingNum > 0) {
        group = this.data.substr(i);
        value = parseInt(group, 10);
        bitBuffer.put(value, remainingNum * 3 + 1);
      }
    };
    module.exports = NumericData;
  }
});

// node_modules/qrcode/lib/core/alphanumeric-data.js
var require_alphanumeric_data = __commonJS({
  "node_modules/qrcode/lib/core/alphanumeric-data.js"(exports, module) {
    var Mode = require_mode();
    var ALPHA_NUM_CHARS = [
      "0",
      "1",
      "2",
      "3",
      "4",
      "5",
      "6",
      "7",
      "8",
      "9",
      "A",
      "B",
      "C",
      "D",
      "E",
      "F",
      "G",
      "H",
      "I",
      "J",
      "K",
      "L",
      "M",
      "N",
      "O",
      "P",
      "Q",
      "R",
      "S",
      "T",
      "U",
      "V",
      "W",
      "X",
      "Y",
      "Z",
      " ",
      "$",
      "%",
      "*",
      "+",
      "-",
      ".",
      "/",
      ":"
    ];
    function AlphanumericData(data) {
      this.mode = Mode.ALPHANUMERIC;
      this.data = data;
    }
    AlphanumericData.getBitsLength = function getBitsLength(length) {
      return 11 * Math.floor(length / 2) + 6 * (length % 2);
    };
    AlphanumericData.prototype.getLength = function getLength() {
      return this.data.length;
    };
    AlphanumericData.prototype.getBitsLength = function getBitsLength() {
      return AlphanumericData.getBitsLength(this.data.length);
    };
    AlphanumericData.prototype.write = function write(bitBuffer) {
      let i;
      for (i = 0; i + 2 <= this.data.length; i += 2) {
        let value = ALPHA_NUM_CHARS.indexOf(this.data[i]) * 45;
        value += ALPHA_NUM_CHARS.indexOf(this.data[i + 1]);
        bitBuffer.put(value, 11);
      }
      if (this.data.length % 2) {
        bitBuffer.put(ALPHA_NUM_CHARS.indexOf(this.data[i]), 6);
      }
    };
    module.exports = AlphanumericData;
  }
});

// node_modules/qrcode/lib/core/byte-data.js
var require_byte_data = __commonJS({
  "node_modules/qrcode/lib/core/byte-data.js"(exports, module) {
    var Mode = require_mode();
    function ByteData(data) {
      this.mode = Mode.BYTE;
      if (typeof data === "string") {
        this.data = new TextEncoder().encode(data);
      } else {
        this.data = new Uint8Array(data);
      }
    }
    ByteData.getBitsLength = function getBitsLength(length) {
      return length * 8;
    };
    ByteData.prototype.getLength = function getLength() {
      return this.data.length;
    };
    ByteData.prototype.getBitsLength = function getBitsLength() {
      return ByteData.getBitsLength(this.data.length);
    };
    ByteData.prototype.write = function(bitBuffer) {
      for (let i = 0, l = this.data.length; i < l; i++) {
        bitBuffer.put(this.data[i], 8);
      }
    };
    module.exports = ByteData;
  }
});

// node_modules/qrcode/lib/core/kanji-data.js
var require_kanji_data = __commonJS({
  "node_modules/qrcode/lib/core/kanji-data.js"(exports, module) {
    var Mode = require_mode();
    var Utils = require_utils();
    function KanjiData(data) {
      this.mode = Mode.KANJI;
      this.data = data;
    }
    KanjiData.getBitsLength = function getBitsLength(length) {
      return length * 13;
    };
    KanjiData.prototype.getLength = function getLength() {
      return this.data.length;
    };
    KanjiData.prototype.getBitsLength = function getBitsLength() {
      return KanjiData.getBitsLength(this.data.length);
    };
    KanjiData.prototype.write = function(bitBuffer) {
      let i;
      for (i = 0; i < this.data.length; i++) {
        let value = Utils.toSJIS(this.data[i]);
        if (value >= 33088 && value <= 40956) {
          value -= 33088;
        } else if (value >= 57408 && value <= 60351) {
          value -= 49472;
        } else {
          throw new Error(
            "Invalid SJIS character: " + this.data[i] + "\nMake sure your charset is UTF-8"
          );
        }
        value = (value >>> 8 & 255) * 192 + (value & 255);
        bitBuffer.put(value, 13);
      }
    };
    module.exports = KanjiData;
  }
});

// node_modules/dijkstrajs/dijkstra.js
var require_dijkstra = __commonJS({
  "node_modules/dijkstrajs/dijkstra.js"(exports, module) {
    "use strict";
    var dijkstra = {
      single_source_shortest_paths: function(graph, s, d) {
        var predecessors = {};
        var costs = {};
        costs[s] = 0;
        var open = dijkstra.PriorityQueue.make();
        open.push(s, 0);
        var closest, u, v, cost_of_s_to_u, adjacent_nodes, cost_of_e, cost_of_s_to_u_plus_cost_of_e, cost_of_s_to_v, first_visit;
        while (!open.empty()) {
          closest = open.pop();
          u = closest.value;
          cost_of_s_to_u = closest.cost;
          adjacent_nodes = graph[u] || {};
          for (v in adjacent_nodes) {
            if (adjacent_nodes.hasOwnProperty(v)) {
              cost_of_e = adjacent_nodes[v];
              cost_of_s_to_u_plus_cost_of_e = cost_of_s_to_u + cost_of_e;
              cost_of_s_to_v = costs[v];
              first_visit = typeof costs[v] === "undefined";
              if (first_visit || cost_of_s_to_v > cost_of_s_to_u_plus_cost_of_e) {
                costs[v] = cost_of_s_to_u_plus_cost_of_e;
                open.push(v, cost_of_s_to_u_plus_cost_of_e);
                predecessors[v] = u;
              }
            }
          }
        }
        if (typeof d !== "undefined" && typeof costs[d] === "undefined") {
          var msg = ["Could not find a path from ", s, " to ", d, "."].join("");
          throw new Error(msg);
        }
        return predecessors;
      },
      extract_shortest_path_from_predecessor_list: function(predecessors, d) {
        var nodes = [];
        var u = d;
        var predecessor;
        while (u) {
          nodes.push(u);
          predecessor = predecessors[u];
          u = predecessors[u];
        }
        nodes.reverse();
        return nodes;
      },
      find_path: function(graph, s, d) {
        var predecessors = dijkstra.single_source_shortest_paths(graph, s, d);
        return dijkstra.extract_shortest_path_from_predecessor_list(
          predecessors,
          d
        );
      },
      /**
       * A very naive priority queue implementation.
       */
      PriorityQueue: {
        make: function(opts) {
          var T = dijkstra.PriorityQueue, t2 = {}, key;
          opts = opts || {};
          for (key in T) {
            if (T.hasOwnProperty(key)) {
              t2[key] = T[key];
            }
          }
          t2.queue = [];
          t2.sorter = opts.sorter || T.default_sorter;
          return t2;
        },
        default_sorter: function(a, b) {
          return a.cost - b.cost;
        },
        /**
         * Add a new item to the queue and ensure the highest priority element
         * is at the front of the queue.
         */
        push: function(value, cost) {
          var item = { value, cost };
          this.queue.push(item);
          this.queue.sort(this.sorter);
        },
        /**
         * Return the highest priority element in the queue.
         */
        pop: function() {
          return this.queue.shift();
        },
        empty: function() {
          return this.queue.length === 0;
        }
      }
    };
    if (typeof module !== "undefined") {
      module.exports = dijkstra;
    }
  }
});

// node_modules/qrcode/lib/core/segments.js
var require_segments = __commonJS({
  "node_modules/qrcode/lib/core/segments.js"(exports) {
    var Mode = require_mode();
    var NumericData = require_numeric_data();
    var AlphanumericData = require_alphanumeric_data();
    var ByteData = require_byte_data();
    var KanjiData = require_kanji_data();
    var Regex = require_regex();
    var Utils = require_utils();
    var dijkstra = require_dijkstra();
    function getStringByteLength(str) {
      return unescape(encodeURIComponent(str)).length;
    }
    function getSegments(regex, mode, str) {
      const segments = [];
      let result;
      while ((result = regex.exec(str)) !== null) {
        segments.push({
          data: result[0],
          index: result.index,
          mode,
          length: result[0].length
        });
      }
      return segments;
    }
    function getSegmentsFromString(dataStr) {
      const numSegs = getSegments(Regex.NUMERIC, Mode.NUMERIC, dataStr);
      const alphaNumSegs = getSegments(Regex.ALPHANUMERIC, Mode.ALPHANUMERIC, dataStr);
      let byteSegs;
      let kanjiSegs;
      if (Utils.isKanjiModeEnabled()) {
        byteSegs = getSegments(Regex.BYTE, Mode.BYTE, dataStr);
        kanjiSegs = getSegments(Regex.KANJI, Mode.KANJI, dataStr);
      } else {
        byteSegs = getSegments(Regex.BYTE_KANJI, Mode.BYTE, dataStr);
        kanjiSegs = [];
      }
      const segs = numSegs.concat(alphaNumSegs, byteSegs, kanjiSegs);
      return segs.sort(function(s1, s2) {
        return s1.index - s2.index;
      }).map(function(obj) {
        return {
          data: obj.data,
          mode: obj.mode,
          length: obj.length
        };
      });
    }
    function getSegmentBitsLength(length, mode) {
      switch (mode) {
        case Mode.NUMERIC:
          return NumericData.getBitsLength(length);
        case Mode.ALPHANUMERIC:
          return AlphanumericData.getBitsLength(length);
        case Mode.KANJI:
          return KanjiData.getBitsLength(length);
        case Mode.BYTE:
          return ByteData.getBitsLength(length);
      }
    }
    function mergeSegments(segs) {
      return segs.reduce(function(acc, curr) {
        const prevSeg = acc.length - 1 >= 0 ? acc[acc.length - 1] : null;
        if (prevSeg && prevSeg.mode === curr.mode) {
          acc[acc.length - 1].data += curr.data;
          return acc;
        }
        acc.push(curr);
        return acc;
      }, []);
    }
    function buildNodes(segs) {
      const nodes = [];
      for (let i = 0; i < segs.length; i++) {
        const seg = segs[i];
        switch (seg.mode) {
          case Mode.NUMERIC:
            nodes.push([
              seg,
              { data: seg.data, mode: Mode.ALPHANUMERIC, length: seg.length },
              { data: seg.data, mode: Mode.BYTE, length: seg.length }
            ]);
            break;
          case Mode.ALPHANUMERIC:
            nodes.push([
              seg,
              { data: seg.data, mode: Mode.BYTE, length: seg.length }
            ]);
            break;
          case Mode.KANJI:
            nodes.push([
              seg,
              { data: seg.data, mode: Mode.BYTE, length: getStringByteLength(seg.data) }
            ]);
            break;
          case Mode.BYTE:
            nodes.push([
              { data: seg.data, mode: Mode.BYTE, length: getStringByteLength(seg.data) }
            ]);
        }
      }
      return nodes;
    }
    function buildGraph(nodes, version) {
      const table = {};
      const graph = { start: {} };
      let prevNodeIds = ["start"];
      for (let i = 0; i < nodes.length; i++) {
        const nodeGroup = nodes[i];
        const currentNodeIds = [];
        for (let j = 0; j < nodeGroup.length; j++) {
          const node = nodeGroup[j];
          const key = "" + i + j;
          currentNodeIds.push(key);
          table[key] = { node, lastCount: 0 };
          graph[key] = {};
          for (let n = 0; n < prevNodeIds.length; n++) {
            const prevNodeId = prevNodeIds[n];
            if (table[prevNodeId] && table[prevNodeId].node.mode === node.mode) {
              graph[prevNodeId][key] = getSegmentBitsLength(table[prevNodeId].lastCount + node.length, node.mode) - getSegmentBitsLength(table[prevNodeId].lastCount, node.mode);
              table[prevNodeId].lastCount += node.length;
            } else {
              if (table[prevNodeId]) table[prevNodeId].lastCount = node.length;
              graph[prevNodeId][key] = getSegmentBitsLength(node.length, node.mode) + 4 + Mode.getCharCountIndicator(node.mode, version);
            }
          }
        }
        prevNodeIds = currentNodeIds;
      }
      for (let n = 0; n < prevNodeIds.length; n++) {
        graph[prevNodeIds[n]].end = 0;
      }
      return { map: graph, table };
    }
    function buildSingleSegment(data, modesHint) {
      let mode;
      const bestMode = Mode.getBestModeForData(data);
      mode = Mode.from(modesHint, bestMode);
      if (mode !== Mode.BYTE && mode.bit < bestMode.bit) {
        throw new Error('"' + data + '" cannot be encoded with mode ' + Mode.toString(mode) + ".\n Suggested mode is: " + Mode.toString(bestMode));
      }
      if (mode === Mode.KANJI && !Utils.isKanjiModeEnabled()) {
        mode = Mode.BYTE;
      }
      switch (mode) {
        case Mode.NUMERIC:
          return new NumericData(data);
        case Mode.ALPHANUMERIC:
          return new AlphanumericData(data);
        case Mode.KANJI:
          return new KanjiData(data);
        case Mode.BYTE:
          return new ByteData(data);
      }
    }
    exports.fromArray = function fromArray(array) {
      return array.reduce(function(acc, seg) {
        if (typeof seg === "string") {
          acc.push(buildSingleSegment(seg, null));
        } else if (seg.data) {
          acc.push(buildSingleSegment(seg.data, seg.mode));
        }
        return acc;
      }, []);
    };
    exports.fromString = function fromString(data, version) {
      const segs = getSegmentsFromString(data, Utils.isKanjiModeEnabled());
      const nodes = buildNodes(segs);
      const graph = buildGraph(nodes, version);
      const path = dijkstra.find_path(graph.map, "start", "end");
      const optimizedSegs = [];
      for (let i = 1; i < path.length - 1; i++) {
        optimizedSegs.push(graph.table[path[i]].node);
      }
      return exports.fromArray(mergeSegments(optimizedSegs));
    };
    exports.rawSplit = function rawSplit(data) {
      return exports.fromArray(
        getSegmentsFromString(data, Utils.isKanjiModeEnabled())
      );
    };
  }
});

// node_modules/qrcode/lib/core/qrcode.js
var require_qrcode = __commonJS({
  "node_modules/qrcode/lib/core/qrcode.js"(exports) {
    var Utils = require_utils();
    var ECLevel = require_error_correction_level();
    var BitBuffer = require_bit_buffer();
    var BitMatrix = require_bit_matrix();
    var AlignmentPattern = require_alignment_pattern();
    var FinderPattern = require_finder_pattern();
    var MaskPattern = require_mask_pattern();
    var ECCode = require_error_correction_code();
    var ReedSolomonEncoder = require_reed_solomon_encoder();
    var Version = require_version();
    var FormatInfo = require_format_info();
    var Mode = require_mode();
    var Segments = require_segments();
    function setupFinderPattern(matrix, version) {
      const size = matrix.size;
      const pos = FinderPattern.getPositions(version);
      for (let i = 0; i < pos.length; i++) {
        const row = pos[i][0];
        const col = pos[i][1];
        for (let r = -1; r <= 7; r++) {
          if (row + r <= -1 || size <= row + r) continue;
          for (let c = -1; c <= 7; c++) {
            if (col + c <= -1 || size <= col + c) continue;
            if (r >= 0 && r <= 6 && (c === 0 || c === 6) || c >= 0 && c <= 6 && (r === 0 || r === 6) || r >= 2 && r <= 4 && c >= 2 && c <= 4) {
              matrix.set(row + r, col + c, true, true);
            } else {
              matrix.set(row + r, col + c, false, true);
            }
          }
        }
      }
    }
    function setupTimingPattern(matrix) {
      const size = matrix.size;
      for (let r = 8; r < size - 8; r++) {
        const value = r % 2 === 0;
        matrix.set(r, 6, value, true);
        matrix.set(6, r, value, true);
      }
    }
    function setupAlignmentPattern(matrix, version) {
      const pos = AlignmentPattern.getPositions(version);
      for (let i = 0; i < pos.length; i++) {
        const row = pos[i][0];
        const col = pos[i][1];
        for (let r = -2; r <= 2; r++) {
          for (let c = -2; c <= 2; c++) {
            if (r === -2 || r === 2 || c === -2 || c === 2 || r === 0 && c === 0) {
              matrix.set(row + r, col + c, true, true);
            } else {
              matrix.set(row + r, col + c, false, true);
            }
          }
        }
      }
    }
    function setupVersionInfo(matrix, version) {
      const size = matrix.size;
      const bits = Version.getEncodedBits(version);
      let row, col, mod;
      for (let i = 0; i < 18; i++) {
        row = Math.floor(i / 3);
        col = i % 3 + size - 8 - 3;
        mod = (bits >> i & 1) === 1;
        matrix.set(row, col, mod, true);
        matrix.set(col, row, mod, true);
      }
    }
    function setupFormatInfo(matrix, errorCorrectionLevel, maskPattern) {
      const size = matrix.size;
      const bits = FormatInfo.getEncodedBits(errorCorrectionLevel, maskPattern);
      let i, mod;
      for (i = 0; i < 15; i++) {
        mod = (bits >> i & 1) === 1;
        if (i < 6) {
          matrix.set(i, 8, mod, true);
        } else if (i < 8) {
          matrix.set(i + 1, 8, mod, true);
        } else {
          matrix.set(size - 15 + i, 8, mod, true);
        }
        if (i < 8) {
          matrix.set(8, size - i - 1, mod, true);
        } else if (i < 9) {
          matrix.set(8, 15 - i - 1 + 1, mod, true);
        } else {
          matrix.set(8, 15 - i - 1, mod, true);
        }
      }
      matrix.set(size - 8, 8, 1, true);
    }
    function setupData(matrix, data) {
      const size = matrix.size;
      let inc = -1;
      let row = size - 1;
      let bitIndex = 7;
      let byteIndex = 0;
      for (let col = size - 1; col > 0; col -= 2) {
        if (col === 6) col--;
        while (true) {
          for (let c = 0; c < 2; c++) {
            if (!matrix.isReserved(row, col - c)) {
              let dark = false;
              if (byteIndex < data.length) {
                dark = (data[byteIndex] >>> bitIndex & 1) === 1;
              }
              matrix.set(row, col - c, dark);
              bitIndex--;
              if (bitIndex === -1) {
                byteIndex++;
                bitIndex = 7;
              }
            }
          }
          row += inc;
          if (row < 0 || size <= row) {
            row -= inc;
            inc = -inc;
            break;
          }
        }
      }
    }
    function createData(version, errorCorrectionLevel, segments) {
      const buffer = new BitBuffer();
      segments.forEach(function(data) {
        buffer.put(data.mode.bit, 4);
        buffer.put(data.getLength(), Mode.getCharCountIndicator(data.mode, version));
        data.write(buffer);
      });
      const totalCodewords = Utils.getSymbolTotalCodewords(version);
      const ecTotalCodewords = ECCode.getTotalCodewordsCount(version, errorCorrectionLevel);
      const dataTotalCodewordsBits = (totalCodewords - ecTotalCodewords) * 8;
      if (buffer.getLengthInBits() + 4 <= dataTotalCodewordsBits) {
        buffer.put(0, 4);
      }
      while (buffer.getLengthInBits() % 8 !== 0) {
        buffer.putBit(0);
      }
      const remainingByte = (dataTotalCodewordsBits - buffer.getLengthInBits()) / 8;
      for (let i = 0; i < remainingByte; i++) {
        buffer.put(i % 2 ? 17 : 236, 8);
      }
      return createCodewords(buffer, version, errorCorrectionLevel);
    }
    function createCodewords(bitBuffer, version, errorCorrectionLevel) {
      const totalCodewords = Utils.getSymbolTotalCodewords(version);
      const ecTotalCodewords = ECCode.getTotalCodewordsCount(version, errorCorrectionLevel);
      const dataTotalCodewords = totalCodewords - ecTotalCodewords;
      const ecTotalBlocks = ECCode.getBlocksCount(version, errorCorrectionLevel);
      const blocksInGroup2 = totalCodewords % ecTotalBlocks;
      const blocksInGroup1 = ecTotalBlocks - blocksInGroup2;
      const totalCodewordsInGroup1 = Math.floor(totalCodewords / ecTotalBlocks);
      const dataCodewordsInGroup1 = Math.floor(dataTotalCodewords / ecTotalBlocks);
      const dataCodewordsInGroup2 = dataCodewordsInGroup1 + 1;
      const ecCount = totalCodewordsInGroup1 - dataCodewordsInGroup1;
      const rs = new ReedSolomonEncoder(ecCount);
      let offset = 0;
      const dcData = new Array(ecTotalBlocks);
      const ecData = new Array(ecTotalBlocks);
      let maxDataSize = 0;
      const buffer = new Uint8Array(bitBuffer.buffer);
      for (let b = 0; b < ecTotalBlocks; b++) {
        const dataSize = b < blocksInGroup1 ? dataCodewordsInGroup1 : dataCodewordsInGroup2;
        dcData[b] = buffer.slice(offset, offset + dataSize);
        ecData[b] = rs.encode(dcData[b]);
        offset += dataSize;
        maxDataSize = Math.max(maxDataSize, dataSize);
      }
      const data = new Uint8Array(totalCodewords);
      let index = 0;
      let i, r;
      for (i = 0; i < maxDataSize; i++) {
        for (r = 0; r < ecTotalBlocks; r++) {
          if (i < dcData[r].length) {
            data[index++] = dcData[r][i];
          }
        }
      }
      for (i = 0; i < ecCount; i++) {
        for (r = 0; r < ecTotalBlocks; r++) {
          data[index++] = ecData[r][i];
        }
      }
      return data;
    }
    function createSymbol(data, version, errorCorrectionLevel, maskPattern) {
      let segments;
      if (Array.isArray(data)) {
        segments = Segments.fromArray(data);
      } else if (typeof data === "string") {
        let estimatedVersion = version;
        if (!estimatedVersion) {
          const rawSegments = Segments.rawSplit(data);
          estimatedVersion = Version.getBestVersionForData(rawSegments, errorCorrectionLevel);
        }
        segments = Segments.fromString(data, estimatedVersion || 40);
      } else {
        throw new Error("Invalid data");
      }
      const bestVersion = Version.getBestVersionForData(segments, errorCorrectionLevel);
      if (!bestVersion) {
        throw new Error("The amount of data is too big to be stored in a QR Code");
      }
      if (!version) {
        version = bestVersion;
      } else if (version < bestVersion) {
        throw new Error(
          "\nThe chosen QR Code version cannot contain this amount of data.\nMinimum version required to store current data is: " + bestVersion + ".\n"
        );
      }
      const dataBits = createData(version, errorCorrectionLevel, segments);
      const moduleCount = Utils.getSymbolSize(version);
      const modules = new BitMatrix(moduleCount);
      setupFinderPattern(modules, version);
      setupTimingPattern(modules);
      setupAlignmentPattern(modules, version);
      setupFormatInfo(modules, errorCorrectionLevel, 0);
      if (version >= 7) {
        setupVersionInfo(modules, version);
      }
      setupData(modules, dataBits);
      if (isNaN(maskPattern)) {
        maskPattern = MaskPattern.getBestMask(
          modules,
          setupFormatInfo.bind(null, modules, errorCorrectionLevel)
        );
      }
      MaskPattern.applyMask(maskPattern, modules);
      setupFormatInfo(modules, errorCorrectionLevel, maskPattern);
      return {
        modules,
        version,
        errorCorrectionLevel,
        maskPattern,
        segments
      };
    }
    exports.create = function create(data, options) {
      if (typeof data === "undefined" || data === "") {
        throw new Error("No input text");
      }
      let errorCorrectionLevel = ECLevel.M;
      let version;
      let mask;
      if (typeof options !== "undefined") {
        errorCorrectionLevel = ECLevel.from(options.errorCorrectionLevel, ECLevel.M);
        version = Version.from(options.version);
        mask = MaskPattern.from(options.maskPattern);
        if (options.toSJISFunc) {
          Utils.setToSJISFunction(options.toSJISFunc);
        }
      }
      return createSymbol(data, version, errorCorrectionLevel, mask);
    };
  }
});

// node_modules/qrcode/lib/renderer/utils.js
var require_utils2 = __commonJS({
  "node_modules/qrcode/lib/renderer/utils.js"(exports) {
    function hex2rgba(hex) {
      if (typeof hex === "number") {
        hex = hex.toString();
      }
      if (typeof hex !== "string") {
        throw new Error("Color should be defined as hex string");
      }
      let hexCode = hex.slice().replace("#", "").split("");
      if (hexCode.length < 3 || hexCode.length === 5 || hexCode.length > 8) {
        throw new Error("Invalid hex color: " + hex);
      }
      if (hexCode.length === 3 || hexCode.length === 4) {
        hexCode = Array.prototype.concat.apply([], hexCode.map(function(c) {
          return [c, c];
        }));
      }
      if (hexCode.length === 6) hexCode.push("F", "F");
      const hexValue = parseInt(hexCode.join(""), 16);
      return {
        r: hexValue >> 24 & 255,
        g: hexValue >> 16 & 255,
        b: hexValue >> 8 & 255,
        a: hexValue & 255,
        hex: "#" + hexCode.slice(0, 6).join("")
      };
    }
    exports.getOptions = function getOptions(options) {
      if (!options) options = {};
      if (!options.color) options.color = {};
      const margin = typeof options.margin === "undefined" || options.margin === null || options.margin < 0 ? 4 : options.margin;
      const width = options.width && options.width >= 21 ? options.width : void 0;
      const scale = options.scale || 4;
      return {
        width,
        scale: width ? 4 : scale,
        margin,
        color: {
          dark: hex2rgba(options.color.dark || "#000000ff"),
          light: hex2rgba(options.color.light || "#ffffffff")
        },
        type: options.type,
        rendererOpts: options.rendererOpts || {}
      };
    };
    exports.getScale = function getScale(qrSize, opts) {
      return opts.width && opts.width >= qrSize + opts.margin * 2 ? opts.width / (qrSize + opts.margin * 2) : opts.scale;
    };
    exports.getImageWidth = function getImageWidth(qrSize, opts) {
      const scale = exports.getScale(qrSize, opts);
      return Math.floor((qrSize + opts.margin * 2) * scale);
    };
    exports.qrToImageData = function qrToImageData(imgData, qr, opts) {
      const size = qr.modules.size;
      const data = qr.modules.data;
      const scale = exports.getScale(size, opts);
      const symbolSize = Math.floor((size + opts.margin * 2) * scale);
      const scaledMargin = opts.margin * scale;
      const palette = [opts.color.light, opts.color.dark];
      for (let i = 0; i < symbolSize; i++) {
        for (let j = 0; j < symbolSize; j++) {
          let posDst = (i * symbolSize + j) * 4;
          let pxColor = opts.color.light;
          if (i >= scaledMargin && j >= scaledMargin && i < symbolSize - scaledMargin && j < symbolSize - scaledMargin) {
            const iSrc = Math.floor((i - scaledMargin) / scale);
            const jSrc = Math.floor((j - scaledMargin) / scale);
            pxColor = palette[data[iSrc * size + jSrc] ? 1 : 0];
          }
          imgData[posDst++] = pxColor.r;
          imgData[posDst++] = pxColor.g;
          imgData[posDst++] = pxColor.b;
          imgData[posDst] = pxColor.a;
        }
      }
    };
  }
});

// node_modules/qrcode/lib/renderer/canvas.js
var require_canvas = __commonJS({
  "node_modules/qrcode/lib/renderer/canvas.js"(exports) {
    var Utils = require_utils2();
    function clearCanvas(ctx, canvas, size) {
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      if (!canvas.style) canvas.style = {};
      canvas.height = size;
      canvas.width = size;
      canvas.style.height = size + "px";
      canvas.style.width = size + "px";
    }
    function getCanvasElement() {
      try {
        return document.createElement("canvas");
      } catch (e) {
        throw new Error("You need to specify a canvas element");
      }
    }
    exports.render = function render(qrData, canvas, options) {
      let opts = options;
      let canvasEl = canvas;
      if (typeof opts === "undefined" && (!canvas || !canvas.getContext)) {
        opts = canvas;
        canvas = void 0;
      }
      if (!canvas) {
        canvasEl = getCanvasElement();
      }
      opts = Utils.getOptions(opts);
      const size = Utils.getImageWidth(qrData.modules.size, opts);
      const ctx = canvasEl.getContext("2d");
      const image = ctx.createImageData(size, size);
      Utils.qrToImageData(image.data, qrData, opts);
      clearCanvas(ctx, canvasEl, size);
      ctx.putImageData(image, 0, 0);
      return canvasEl;
    };
    exports.renderToDataURL = function renderToDataURL(qrData, canvas, options) {
      let opts = options;
      if (typeof opts === "undefined" && (!canvas || !canvas.getContext)) {
        opts = canvas;
        canvas = void 0;
      }
      if (!opts) opts = {};
      const canvasEl = exports.render(qrData, canvas, opts);
      const type = opts.type || "image/png";
      const rendererOpts = opts.rendererOpts || {};
      return canvasEl.toDataURL(type, rendererOpts.quality);
    };
  }
});

// node_modules/qrcode/lib/renderer/svg-tag.js
var require_svg_tag = __commonJS({
  "node_modules/qrcode/lib/renderer/svg-tag.js"(exports) {
    var Utils = require_utils2();
    function getColorAttrib(color, attrib) {
      const alpha = color.a / 255;
      const str = attrib + '="' + color.hex + '"';
      return alpha < 1 ? str + " " + attrib + '-opacity="' + alpha.toFixed(2).slice(1) + '"' : str;
    }
    function svgCmd(cmd, x, y) {
      let str = cmd + x;
      if (typeof y !== "undefined") str += " " + y;
      return str;
    }
    function qrToPath(data, size, margin) {
      let path = "";
      let moveBy = 0;
      let newRow = false;
      let lineLength = 0;
      for (let i = 0; i < data.length; i++) {
        const col = Math.floor(i % size);
        const row = Math.floor(i / size);
        if (!col && !newRow) newRow = true;
        if (data[i]) {
          lineLength++;
          if (!(i > 0 && col > 0 && data[i - 1])) {
            path += newRow ? svgCmd("M", col + margin, 0.5 + row + margin) : svgCmd("m", moveBy, 0);
            moveBy = 0;
            newRow = false;
          }
          if (!(col + 1 < size && data[i + 1])) {
            path += svgCmd("h", lineLength);
            lineLength = 0;
          }
        } else {
          moveBy++;
        }
      }
      return path;
    }
    exports.render = function render(qrData, options, cb) {
      const opts = Utils.getOptions(options);
      const size = qrData.modules.size;
      const data = qrData.modules.data;
      const qrcodesize = size + opts.margin * 2;
      const bg = !opts.color.light.a ? "" : "<path " + getColorAttrib(opts.color.light, "fill") + ' d="M0 0h' + qrcodesize + "v" + qrcodesize + 'H0z"/>';
      const path = "<path " + getColorAttrib(opts.color.dark, "stroke") + ' d="' + qrToPath(data, size, opts.margin) + '"/>';
      const viewBox = 'viewBox="0 0 ' + qrcodesize + " " + qrcodesize + '"';
      const width = !opts.width ? "" : 'width="' + opts.width + '" height="' + opts.width + '" ';
      const svgTag = '<svg xmlns="http://www.w3.org/2000/svg" ' + width + viewBox + ' shape-rendering="crispEdges">' + bg + path + "</svg>\n";
      if (typeof cb === "function") {
        cb(null, svgTag);
      }
      return svgTag;
    };
  }
});

// node_modules/qrcode/lib/browser.js
var require_browser = __commonJS({
  "node_modules/qrcode/lib/browser.js"(exports) {
    var canPromise = require_can_promise();
    var QRCode2 = require_qrcode();
    var CanvasRenderer = require_canvas();
    var SvgRenderer = require_svg_tag();
    function renderCanvas(renderFunc, canvas, text, opts, cb) {
      const args = [].slice.call(arguments, 1);
      const argsNum = args.length;
      const isLastArgCb = typeof args[argsNum - 1] === "function";
      if (!isLastArgCb && !canPromise()) {
        throw new Error("Callback required as last argument");
      }
      if (isLastArgCb) {
        if (argsNum < 2) {
          throw new Error("Too few arguments provided");
        }
        if (argsNum === 2) {
          cb = text;
          text = canvas;
          canvas = opts = void 0;
        } else if (argsNum === 3) {
          if (canvas.getContext && typeof cb === "undefined") {
            cb = opts;
            opts = void 0;
          } else {
            cb = opts;
            opts = text;
            text = canvas;
            canvas = void 0;
          }
        }
      } else {
        if (argsNum < 1) {
          throw new Error("Too few arguments provided");
        }
        if (argsNum === 1) {
          text = canvas;
          canvas = opts = void 0;
        } else if (argsNum === 2 && !canvas.getContext) {
          opts = text;
          text = canvas;
          canvas = void 0;
        }
        return new Promise(function(resolve, reject) {
          try {
            const data = QRCode2.create(text, opts);
            resolve(renderFunc(data, canvas, opts));
          } catch (e) {
            reject(e);
          }
        });
      }
      try {
        const data = QRCode2.create(text, opts);
        cb(null, renderFunc(data, canvas, opts));
      } catch (e) {
        cb(e);
      }
    }
    exports.create = QRCode2.create;
    exports.toCanvas = renderCanvas.bind(null, CanvasRenderer.render);
    exports.toDataURL = renderCanvas.bind(null, CanvasRenderer.renderToDataURL);
    exports.toString = renderCanvas.bind(null, function(data, _, opts) {
      return SvgRenderer.render(data, opts);
    });
  }
});

// extension/popup.js
var import_qrcode = __toESM(require_browser(), 1);

// lib/otp.js
var BASE32_REGEX = /^[A-Z2-7]+$/;
var OTP_URI_REGEX = /otpauth:\/\/[^\s"'<>]+/gi;
var MIN_PERIOD = 15;
var MAX_PERIOD = 120;
var OTP_TYPES = ["totp", "hotp"];
var OTP_ALGORITHMS = ["SHA1", "SHA256", "SHA512"];
var HMAC_HASH_NAMES = { SHA1: "SHA-1", SHA256: "SHA-256", SHA512: "SHA-512" };
var MAX_SAFE_COUNTER = Number.MAX_SAFE_INTEGER;
var OtpVaultError = class extends Error {
  constructor(message, { code = "OTP_VAULT_ERROR", cause } = {}) {
    super(message, cause ? { cause } : void 0);
    this.name = "OtpVaultError";
    this.code = code;
  }
};
function reportError(context, error) {
  console.error(`[OTP Vault] ${context}`, error);
}
function toUserMessage(error, fallback = "Something went wrong") {
  if (error instanceof Error && error.message) return error.message;
  return fallback;
}
function sanitizeBase32(value) {
  return (value || "").toUpperCase().replace(/\s+/g, "").replace(/=+$/g, "");
}
function normalizeTags(value) {
  const raw = Array.isArray(value) ? value : String(value || "").split(",");
  return [...new Set(
    raw.map((tag) => String(tag).trim().replace(/\s+/g, " ")).filter(Boolean).map((tag) => tag.slice(0, 24))
  )];
}
function generateEntryId() {
  const bytes = globalThis.crypto.getRandomValues(new Uint8Array(6));
  const random = [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
  return `entry_${Date.now().toString(36)}_${random}`;
}
function safeDecode(value) {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}
function ensureBase32Secret(secret) {
  const clean = sanitizeBase32(secret);
  if (!clean) {
    throw new OtpVaultError("Secret is required", { code: "SECRET_REQUIRED" });
  }
  if (!BASE32_REGEX.test(clean)) {
    throw new OtpVaultError("Secret contains invalid Base32 characters", { code: "SECRET_INVALID" });
  }
  if (base32ToBytes(clean).length === 0) {
    throw new OtpVaultError("Secret is too short to decode", { code: "SECRET_TOO_SHORT" });
  }
  return clean;
}
function ensureDigits(digits) {
  const value = Number(digits);
  if (value !== 6 && value !== 8) {
    throw new OtpVaultError("Only 6-digit and 8-digit OTP codes are supported", { code: "DIGITS_UNSUPPORTED" });
  }
  return value;
}
function ensurePeriod(period) {
  const value = Number(period);
  if (!Number.isInteger(value) || value < MIN_PERIOD || value > MAX_PERIOD) {
    throw new OtpVaultError(`Period must be an integer between ${MIN_PERIOD} and ${MAX_PERIOD} seconds`, {
      code: "PERIOD_INVALID"
    });
  }
  return value;
}
function ensureType(type) {
  const value = String(type || "totp").toLowerCase();
  if (!OTP_TYPES.includes(value)) {
    throw new OtpVaultError("OTP type must be totp or hotp", { code: "OTP_TYPE_INVALID" });
  }
  return value;
}
function ensureAlgorithm(algorithm) {
  const value = String(algorithm || "SHA1").toUpperCase();
  if (!OTP_ALGORITHMS.includes(value)) {
    throw new OtpVaultError("OTP algorithm must be SHA1, SHA256, or SHA512", { code: "ALGORITHM_UNSUPPORTED" });
  }
  return value;
}
function ensureCounter(counter) {
  if (counter === void 0 || counter === null || counter === "") return 0;
  const value = Number(counter);
  if (!Number.isInteger(value) || value < 0 || value > MAX_SAFE_COUNTER) {
    throw new OtpVaultError("HOTP counter must be a non-negative integer", { code: "COUNTER_INVALID" });
  }
  return value;
}
function createFallbackLabel(secret) {
  const clean = sanitizeBase32(secret);
  if (clean.length <= 8) return `Secret ${clean || "entry"}`;
  return `Secret ${clean.slice(0, 4)}...${clean.slice(-4)}`;
}
function normalizeLabel(label, secret) {
  const clean = (label || "").trim();
  return clean || createFallbackLabel(secret);
}
function normalizeEntry(entry) {
  const secret = ensureBase32Secret(entry.secret || "");
  const type = ensureType(entry.type);
  return {
    id: entry.id || generateEntryId(),
    label: normalizeLabel(entry.label, secret),
    secret,
    type,
    counter: type === "hotp" ? ensureCounter(entry.counter) : 0,
    algorithm: ensureAlgorithm(entry.algorithm),
    digits: ensureDigits(entry.digits ?? 6),
    period: ensurePeriod(entry.period ?? 30),
    pinned: Boolean(entry.pinned),
    tags: normalizeTags(entry.tags),
    createdAt: typeof entry.createdAt === "number" ? entry.createdAt : Date.now(),
    order: Number.isFinite(Number(entry.order)) ? Number(entry.order) : 0
  };
}
function normalizeEntries(entries2) {
  if (!Array.isArray(entries2)) return [];
  return entries2.flatMap((entry) => {
    try {
      return [normalizeEntry(entry)];
    } catch {
      return [];
    }
  });
}
function parseLabelParts(label) {
  const clean = (label || "").trim();
  if (!clean) return { issuer: "Unknown", account: "No account label" };
  if (clean.includes(":")) {
    const [issuer, ...rest] = clean.split(":");
    return {
      issuer: issuer.trim() || "Unknown",
      account: rest.join(":").trim() || "No account label"
    };
  }
  if (clean.includes(" - ")) {
    const [issuer, ...rest] = clean.split(" - ");
    return {
      issuer: issuer.trim() || clean,
      account: rest.join(" - ").trim() || "No account label"
    };
  }
  return { issuer: clean, account: "No account label" };
}
function getIssuerInitials(label) {
  const issuer = parseLabelParts(label).issuer;
  const parts = issuer.split(/\s+/).filter(Boolean);
  if (parts.length === 0) return "OT";
  if (parts.length === 1) return parts[0].slice(0, 2).toUpperCase();
  return `${parts[0][0]}${parts[1][0]}`.toUpperCase();
}
function normalizeOtpUriCandidate(value) {
  return safeDecode((value || "").trim()).replace(/[)\],.;]+$/, "");
}
function parseOtpAuthUri(uri) {
  let parsed;
  try {
    parsed = new URL(uri);
  } catch (error) {
    throw new OtpVaultError("OTP URI is not a valid URL", { code: "URI_INVALID", cause: error });
  }
  if (parsed.protocol !== "otpauth:") {
    throw new OtpVaultError("URI must start with otpauth://", { code: "URI_PROTOCOL" });
  }
  const type = parsed.hostname.toLowerCase();
  if (type !== "totp" && type !== "hotp") {
    throw new OtpVaultError("Only TOTP and HOTP URIs are supported", { code: "URI_TYPE" });
  }
  const algorithm = (parsed.searchParams.get("algorithm") || "SHA1").toUpperCase();
  if (!OTP_ALGORITHMS.includes(algorithm)) {
    throw new OtpVaultError("Only SHA1, SHA256, and SHA512 OTP URIs are supported", { code: "URI_ALGORITHM" });
  }
  let counter;
  if (type === "hotp") {
    const counterParam = parsed.searchParams.get("counter");
    counter = counterParam === null ? 0 : Number(counterParam);
    if (!Number.isInteger(counter) || counter < 0 || counter > MAX_SAFE_COUNTER) {
      throw new OtpVaultError("HOTP counter must be a non-negative integer", { code: "URI_COUNTER" });
    }
  }
  const issuerParam = safeDecode(parsed.searchParams.get("issuer") || "").trim();
  const rawLabel = safeDecode(parsed.pathname.replace(/^\/+/, "")).trim();
  const labelParts = parseLabelParts(rawLabel);
  if (issuerParam && rawLabel && labelParts.issuer !== "Unknown" && labelParts.account !== "No account label") {
    if (labelParts.issuer.toLowerCase() !== issuerParam.toLowerCase()) {
      throw new OtpVaultError("OTP URI issuer does not match the label", { code: "URI_ISSUER_MISMATCH" });
    }
  }
  const label = rawLabel ? issuerParam && rawLabel.includes(":") ? labelParts.account === "No account label" ? `${labelParts.issuer === "Unknown" ? issuerParam : labelParts.issuer}:${labelParts.account}` : labelParts.issuer === "Unknown" ? `${issuerParam}:${labelParts.account}` : rawLabel : !issuerParam ? rawLabel : `${issuerParam}:${rawLabel}` : issuerParam ? `${issuerParam}:Imported Account` : "Imported Account";
  return normalizeEntry({
    label,
    secret: parsed.searchParams.get("secret") || "",
    type,
    counter,
    algorithm,
    // Period is meaningless for HOTP but stored so the entry shape stays valid.
    digits: parsed.searchParams.has("digits") ? Number(parsed.searchParams.get("digits")) : 6,
    period: type === "hotp" ? 30 : parsed.searchParams.has("period") ? Number(parsed.searchParams.get("period")) : 30
  });
}
function extractOtpAuthUri(rawText) {
  return extractOtpAuthUris(rawText)[0] || "";
}
function buildOtpAuthUri(entry) {
  const type = String(entry?.type || "totp").toLowerCase() === "hotp" ? "hotp" : "totp";
  const label = String(entry?.label || "").trim() || "Imported Account";
  const params = new URLSearchParams();
  params.set("secret", sanitizeBase32(entry?.secret));
  const algorithm = String(entry?.algorithm || "SHA1").toUpperCase();
  if (algorithm !== "SHA1") params.set("algorithm", algorithm);
  const digits = Number(entry?.digits) === 8 ? 8 : 6;
  if (digits !== 6) params.set("digits", String(digits));
  if (type === "totp") {
    const period = Number(entry?.period) || 30;
    if (period !== 30) params.set("period", String(period));
  } else {
    params.set("counter", String(Math.max(0, Number(entry?.counter) || 0)));
  }
  if (label.includes(":")) params.set("issuer", parseLabelParts(label).issuer);
  return `otpauth://${type}/${encodeURIComponent(label)}?${params.toString()}`;
}
function extractOtpAuthUris(rawText) {
  const candidates = /* @__PURE__ */ new Set();
  const raw = (rawText || "").trim();
  if (!raw) return [];
  candidates.add(normalizeOtpUriCandidate(raw));
  for (const match of raw.matchAll(OTP_URI_REGEX)) {
    candidates.add(normalizeOtpUriCandidate(match[0]));
  }
  const decoded = safeDecode(raw);
  candidates.add(normalizeOtpUriCandidate(decoded));
  for (const match of decoded.matchAll(OTP_URI_REGEX)) {
    candidates.add(normalizeOtpUriCandidate(match[0]));
  }
  const valid = [];
  for (const candidate of candidates) {
    if (!candidate.startsWith("otpauth://")) continue;
    try {
      parseOtpAuthUri(candidate);
      valid.push(candidate);
    } catch {
      continue;
    }
  }
  return valid;
}
function hasDuplicateEntry(entries2, candidate) {
  return entries2.some((entry) => entry.secret === candidate.secret && entry.digits === candidate.digits && entry.period === candidate.period);
}
function compareEntries(a, b, sortBy = "pinned-alpha") {
  if (sortBy === "recent") return b.createdAt - a.createdAt;
  if (sortBy === "period") return a.period - b.period || a.label.localeCompare(b.label, void 0, { sensitivity: "base" });
  if (sortBy === "custom") return a.order - b.order || a.label.localeCompare(b.label, void 0, { sensitivity: "base" });
  if (a.pinned !== b.pinned) return a.pinned ? -1 : 1;
  return a.label.localeCompare(b.label, void 0, { sensitivity: "base" });
}
function computeDropIndex(midpoints, fromIndex, y) {
  if (!Array.isArray(midpoints) || midpoints.length === 0) return 0;
  const others = midpoints.filter((_, index) => index !== fromIndex);
  if (!Number.isFinite(y) || others.length === 0) return others.length;
  for (let index = 0; index < others.length; index += 1) {
    if (y <= others[index]) return index;
  }
  return others.length;
}
function base32ToBytes(base32) {
  const clean = sanitizeBase32(base32);
  if (!clean) return new Uint8Array();
  let bits = "";
  for (const char of clean) {
    const idx = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".indexOf(char);
    if (idx === -1) {
      throw new OtpVaultError("Secret contains invalid Base32 characters", { code: "SECRET_INVALID" });
    }
    bits += idx.toString(2).padStart(5, "0");
  }
  const bytes = [];
  for (let index = 0; index + 8 <= bits.length; index += 8) {
    bytes.push(Number.parseInt(bits.slice(index, index + 8), 2));
  }
  return new Uint8Array(bytes);
}
var MIGRATION_URI_REGEX = /otpauth-migration:\/\/[^\s"'<>]+/gi;
function extractMigrationUris(rawText) {
  const found = /* @__PURE__ */ new Set();
  const raw = (rawText || "").trim();
  if (!raw) return [];
  for (const match of raw.matchAll(MIGRATION_URI_REGEX)) {
    found.add(match[0]);
  }
  for (const match of safeDecode(raw).matchAll(MIGRATION_URI_REGEX)) {
    found.add(match[0]);
  }
  return [...found];
}
function toCounterBytes(counter) {
  const bytes = new Uint8Array(8);
  let value = BigInt(counter);
  for (let index = 7; index >= 0; index -= 1) {
    bytes[index] = Number(value & 0xffn);
    value >>= 8n;
  }
  return bytes;
}
async function hmac(keyBytes, messageBytes, hash, cryptoApi = globalThis.crypto) {
  if (!cryptoApi?.subtle) {
    throw new OtpVaultError("Browser crypto support is unavailable", { code: "CRYPTO_UNAVAILABLE" });
  }
  const algorithmName = HMAC_HASH_NAMES[hash] || hash;
  const key = await cryptoApi.subtle.importKey("raw", keyBytes, { name: "HMAC", hash: algorithmName }, false, ["sign"]);
  const signature = await cryptoApi.subtle.sign("HMAC", key, messageBytes);
  return new Uint8Array(signature);
}
function truncateDigest(digest, digits) {
  const offset = digest[digest.length - 1] & 15;
  const binary = (digest[offset] & 127) << 24 | digest[offset + 1] << 16 | digest[offset + 2] << 8 | digest[offset + 3];
  return (binary % 10 ** digits).toString().padStart(digits, "0");
}
async function generateHotp(secret, counter, digits, algorithm = "SHA1", cryptoApi = globalThis.crypto) {
  const normalizedSecret = ensureBase32Secret(secret);
  const normalizedCounter = ensureCounter(counter);
  const normalizedDigits = ensureDigits(digits);
  const normalizedAlgorithm = ensureAlgorithm(algorithm);
  const digest = await hmac(
    base32ToBytes(normalizedSecret),
    toCounterBytes(normalizedCounter),
    normalizedAlgorithm,
    cryptoApi
  );
  return truncateDigest(digest, normalizedDigits);
}
async function generateTotp(secret, digits, period, now, algorithm = "SHA1", cryptoApi = globalThis.crypto) {
  const normalizedSecret = ensureBase32Secret(secret);
  const normalizedDigits = ensureDigits(digits);
  const normalizedPeriod = ensurePeriod(period);
  const normalizedAlgorithm = ensureAlgorithm(algorithm);
  const counter = Math.floor(now / normalizedPeriod);
  const digest = await hmac(
    base32ToBytes(normalizedSecret),
    toCounterBytes(counter),
    normalizedAlgorithm,
    cryptoApi
  );
  return truncateDigest(digest, normalizedDigits);
}
function formatCode(code) {
  if (code.length === 6) return `${code.slice(0, 3)} ${code.slice(3)}`;
  if (code.length === 8) return `${code.slice(0, 4)} ${code.slice(4)}`;
  return code;
}

// lib/i18n.js
var DEFAULT_LOCALE = "en";
var PLACEHOLDER_PATTERN = /\{([a-zA-Z0-9_]+)\}/g;
var en = {
  // Toast titles
  "toast.vaultTitle": "Vault",
  "toast.importTitle": "Import",
  "toast.settingsTitle": "Settings",
  "toast.hotpCounterTitle": "HOTP counter",
  "toast.copyFailed": "Could not copy OTP to clipboard",
  // Unlock panel — web app (index.html #unlock-panel)
  "unlock.eyebrow": "vault state",
  "unlock.title": "Vault locked on this device",
  "unlock.helper": "Unlock with your passphrase to read encrypted entries stored locally.",
  "unlock.passphrasePlaceholder": "Enter vault passphrase",
  "unlock.button": "Unlock Vault",
  "unlock.biometricButton": "Unlock with biometrics",
  "unlock.statusSuccess": "Vault unlocked",
  "unlock.statusBiometricSuccess": "Vault unlocked with biometrics",
  "unlock.statusFailed": "Incorrect passphrase or unreadable encrypted vault",
  // Unlock panel — extension popup (popup.html #unlock-panel)
  "unlock.extensionTitle": "Extension Vault",
  "unlock.extensionPassphrasePlaceholder": "Passphrase to unlock encrypted storage",
  "unlock.extensionButton": "Unlock",
  "unlock.extensionStatusSuccess": "Vault unlocked",
  // Common
  "common.cancel": "Cancel",
  "common.close": "Close",
  "common.copy": "Copy",
  "common.copied": "Copied",
  "common.undo": "Undo",
  "common.confirm": "Confirm",
  "common.import": "Import",
  "common.save": "Save",
  "common.remove": "Remove",
  "common.edit": "Edit",
  "common.dismiss": "Dismiss",
  "common.reload": "Reload",
  // Entry actions + metadata
  "entries.headingLocked": "Vault Locked",
  "entries.headingCurrent": "Current Codes",
  "entries.copy": "Copy",
  "entries.copied": "Copied",
  "entries.reveal": "Reveal",
  "entries.hide": "Hide",
  "entries.pin": "Pin",
  "entries.unpin": "Unpin",
  "entries.up": "Up",
  "entries.down": "Down",
  "entries.qr": "QR",
  "entries.invalidSecret": "Invalid secret",
  "entries.invalidShort": "Invalid",
  "entries.counterLeft": "counter #{counter}",
  "entries.secondsLeft": "{seconds}s left",
  "entries.meta": "{digits} digits \u2022 {period}s",
  "entries.pinToggled": "Entry order updated",
  "entries.removed": "Entry removed",
  "entries.updated": "Entry updated",
  "entries.manualOrderUpdated": "Manual order updated",
  "entries.groupAll": "All Entries",
  "entries.groupUntagged": "Untagged",
  "entries.select": "Select entry",
  "entries.reorder": "Reorder entry",
  "entries.dragToReorder": "Drag to reorder",
  // Empty states (web app workspace)
  "empty.heading": "Vault ready for the first import",
  "empty.kicker": "vault",
  "empty.headingLocked": "Vault is locked",
  "empty.headingNoMatch": "No matching entries",
  "empty.locked": "Vault is locked. Unlock to view your codes.",
  "empty.noEntries": "No entries yet. Import a URI, scan a QR, or add one manually.",
  "empty.noMatch": "Adjust the search or clear the filter to see your entries.",
  "empty.addFirst": "Add your first entry",
  "empty.pasteUri": "Paste a URI",
  "empty.scanQr": "Scan a QR code",
  "empty.step1Title": "1. Import or type",
  "empty.step1Text": "Use Base32, URI, clipboard, QR image, or camera.",
  "empty.step2Title": "2. Review and tag",
  "empty.step2Text": "Catch duplicates early and keep the vault organized by project or device.",
  "empty.step3Title": "3. Protect this device",
  "empty.step3Text": "Enable persistence only when needed, then add encryption and backups.",
  // Top bar + workspace
  "topbar.searchPlaceholder": "Search issuer, account, or tag",
  "topbar.searchLabel": "Search entries",
  "topbar.copyHistory": "Copy history",
  "topbar.settings": "Vault settings",
  "topbar.install": "Install App",
  "topbar.lock": "Lock Vault",
  "topbar.add": "+ Add",
  "workspace.summaryAccounts": "Accounts",
  "workspace.summaryPinned": "Pinned",
  "workspace.summaryGroups": "Groups",
  "workspace.summaryStorage": "Storage",
  "workspace.storageEncrypted": "Encrypted",
  "workspace.storageDevice": "Device",
  "workspace.storageSession": "Session",
  "workspace.storageLocked": " (Locked)",
  "workspace.online": "Online",
  "workspace.offlineReady": "Offline Ready",
  "workspace.sortLabel": "Sort",
  "workspace.groupLabel": "Group",
  "workspace.sortPinnedAlpha": "Pinned + A-Z",
  "workspace.sortManual": "Manual order",
  "workspace.sortRecent": "Newest first",
  "workspace.sortPeriod": "Fastest timer first",
  "workspace.groupNone": "No group",
  "workspace.groupIssuer": "Issuer",
  "workspace.groupTag": "First tag",
  "workspace.selectedCount": "{count} selected",
  "workspace.bulkAddTagPlaceholder": "Add tag to selected",
  "workspace.bulkApplyTag": "Apply Tag",
  "workspace.bulkRemove": "Remove Selected",
  // Banners
  "banner.stale": "Vault changed in another tab. This tab is read-only \u2014 reload to pick up the latest vault.",
  "banner.backupReminder": "No vault export in over 30 days \u2014 export a backup from the settings below.",
  "banner.driftPrefix": "Device clock off by",
  "banner.driftSuffix": " \u2014 TOTP codes may be rejected. Fix your system clock.",
  "banner.driftSuffixExtension": " \u2014 TOTP codes may be rejected.",
  // Privacy dialog
  "privacy.eyebrow": "storage warning",
  "privacy.title": "Before enabling device storage",
  "privacy.text": "Your 2FA secrets will be saved in browser storage on this device. Use encrypted storage and only enable this on trusted hardware.",
  "privacy.accept": "I Understand",
  // Add & import sheet
  "add.eyebrow": "vault controls",
  "add.heading": "Add & import entries",
  "add.tabManual": "Manual",
  "add.tabPaste": "Paste",
  "add.tabQr": "QR",
  "add.tabCamera": "Camera",
  "add.panelManual": "Manual entry",
  "add.panelPaste": "Paste URIs",
  "add.panelQrImage": "QR image import",
  "add.panelCamera": "Camera import",
  "add.secretLabel": "Base32 Secret",
  "add.labelLabel": "Label (optional)",
  "add.tagsLabel": "Tags",
  "add.typeLabel": "Type",
  "add.counterLabel": "Counter",
  "add.algorithmLabel": "Algorithm",
  "add.digitsLabel": "Digits",
  "add.periodLabel": "Period (seconds)",
  "add.saveEntry": "Save Entry",
  "add.pasteUrisLabel": "Paste one or many `otpauth://` URIs",
  "add.pastePlaceholder": "Paste one or many OTP URIs here. The vault will preview valid matches before import.",
  "add.importUri": "Import otpauth:// URI",
  "add.importGa": "Import Google Authenticator",
  "add.importClipboard": "Import from clipboard",
  "add.importApps": "Import Aegis / 2FAS",
  "add.qrFileLabel": "QR image file",
  "add.qrFileChoose": "Choose image file\u2026",
  "add.qrUrlLabel": "QR image URL",
  "add.qrUrlPlaceholder": "https://example.com/qr.png",
  "add.cameraHint": "A scan is only accepted after it repeats over two frames, reducing accidental false positives.",
  "add.startCamera": "Start Camera",
  "add.stopCamera": "Stop",
  "add.entryAdded": "Entry added",
  // Import statuses + preview
  "import.readingClipboard": "Reading clipboard...",
  "import.readingQrFile": "Reading QR file...",
  "import.fetchingQrUrl": "Fetching QR image URL...",
  "import.qrUrlRequired": "Please enter a QR image URL",
  "import.invalidUri": "Invalid URI",
  "import.noValidUri": "No valid otpauth:// URI found",
  "import.pasteGaFirst": "Paste your Google Authenticator export (the otpauth-migration:// text or URI) first",
  "import.noGaFound": "No Google Authenticator export found in the pasted text",
  "import.decodingGa": "Decoding Google Authenticator export...",
  "import.noClipboardUri": "Clipboard does not contain a valid OTP URI or QR image",
  "import.noValidOtpUriInQr": "QR code was detected but does not contain a valid OTP URI",
  "import.cameraReady": "Camera ready. Hold a QR code in front of it.",
  "import.cameraStopped": "Camera stopped",
  "import.startingCamera": "Starting camera...",
  "import.scanConfirming": "Potential OTP QR detected. Confirming with another frame...",
  "import.scanProgress": "Scanned {done} of {total} QR codes...",
  "import.scanComplete": "All QR codes scanned.",
  "import.scanMixedBatches": "QR codes from different exports detected \u2014 restart the scan with one export.",
  "import.fileReadFailed": "Failed to import QR file",
  "import.urlReadFailed": "Failed to import from URL",
  "import.clipboardFailed": "Failed to import from clipboard",
  "import.previewTitle": "Review {count} candidate{plural}",
  "import.previewHeading": "Review import candidates",
  "import.previewHint": "The vault only imports entries that pass strict URI validation.",
  "import.previewStatus": "{source}: only valid, non-duplicate entries are shown below.",
  "import.previewSkipped": " Skipped {count} duplicate{plural}.",
  "import.previewInvalid": " Ignored {count} invalid entr{plural}.",
  "import.alreadyInVault": "Already in vault",
  "import.includeEntry": "Import this entry",
  "import.previewLabelField": "Label",
  "import.previewTagsField": "Tags",
  "import.previewTagsPlaceholder": "project, hardware-key",
  "import.applyTagsLabel": "Apply tags to imported entries",
  "import.importEntries": "Import Entries",
  "import.selectAtLeastOne": "Select at least one entry to import",
  "import.importedOne": "{source}: imported 1 entry",
  "import.importedMany": "{source}: imported {count} entries",
  "import.restoredOne": "Restored 1 entry",
  "import.restoredMany": "Restored {count} entries",
  "import.nothingToUndo": "Nothing to undo \u2014 those entries already exist again",
  "import.appsFileFailed": "Could not import the Aegis / 2FAS export",
  "import.appsReading": "Decoding Aegis / 2FAS export...",
  // Google Authenticator camera + undo
  "undo.entryRemovedOne": "Entry removed",
  "undo.entryRemovedMany": "{count} entries removed",
  // Copy history
  "history.eyebrow": "recent activity",
  "history.heading": "Copy History",
  "history.empty": "No copied codes yet. The last few copied OTPs appear here for quick recall.",
  // Settings sheet — web app
  "settings.eyebrow": "privacy",
  "settings.heading": "Device & Backup Controls",
  "settings.persistToggle": "Remember entries on this device",
  "settings.encryptToggle": "Encrypt stored entries with a passphrase",
  "settings.unlockOnLoadToggle": "Require unlock when opening this app",
  "settings.blurCodesToggle": "Blur OTP codes until hovered or focused",
  "settings.screenshotSafeToggle": "Screenshot-safe mode hides codes until revealed",
  "settings.clearClipboardToggle": "Clear clipboard 30 seconds after copy",
  "settings.autoLockLabel": "Auto-lock (encrypted vaults)",
  "settings.autoLockAfter": "After {minutes} minutes idle",
  "settings.autoLockOffOption": "Off",
  "settings.languageLabel": "Language",
  "settings.languageSystem": "Match system",
  "settings.passphraseLabel": "Vault passphrase",
  "settings.passphrasePlaceholder": "Use a strong passphrase",
  "settings.passphraseConfirmLabel": "Confirm passphrase",
  "settings.passphraseConfirmPlaceholder": "Repeat passphrase",
  "settings.passphraseGuidance": "This vault is already encrypted. Use Change Passphrase to rotate your vault secret.",
  "settings.exportBackup": "Export Backup",
  "settings.importBackup": "Import Backup",
  "settings.changePassphrase": "Change Passphrase",
  "settings.checkClockNow": "Check clock now",
  "settings.save": "Save Privacy Settings",
  // Seeded ahead of the planned auto-lock setting
  "settings.autoLock": "Lock vault automatically after {minutes} minutes",
  "settings.autoLockOff": "Auto-lock is off",
  "settings.autoLock5": "After 5 minutes idle",
  "settings.autoLock15": "After 15 minutes idle",
  "settings.autoLock30": "After 30 minutes idle",
  "settings.languageEn": "English",
  "settings.languageVi": "Ti\u1EBFng Vi\u1EC7t",
  "changepass.eyebrow": "vault passphrase",
  "import.previewEyebrow": "import review",
  "settings.themeLabel": "Theme",
  "settings.themeSystem": "Match system",
  "settings.themeLight": "Light",
  "settings.themeDark": "Dark",
  "settings.driftToggle": "Check device clock against server time (needs network)",
  "settings.statusEncryptedVaultSaved": "Encrypted vault saved. Use Change Passphrase to rotate your vault secret.",
  "settings.statusEncryptedSaved": "Encrypted vault saved",
  "settings.statusDeviceStorageUpdated": "Device storage updated",
  "settings.statusSessionOnly": "Entries are now session-only",
  "settings.statusImportFailed": "Could not import backup",
  "settings.statusPassphraseUpdated": "Vault passphrase updated",
  "settings.statusLockRequiresEncryption": "Enable encrypted storage to use lock/unlock",
  "settings.statusSaveFailed": "Could not save settings",
  "settings.statusInstallUnavailable": "Install prompt is not available yet on this browser",
  "settings.biometricEyebrow": "biometric unlock",
  "settings.biometricEnroll": "Enable biometric unlock",
  "settings.biometricDisenroll": "Disable biometric unlock",
  "settings.biometricEnrolled": "Biometric unlock is enrolled on this device. Your passphrase remains the recovery method.",
  "settings.biometricAvailable": "Unlock with your platform authenticator instead of your passphrase. Your passphrase stays as recovery.",
  "settings.biometricNeedsEncryption": "Enable encrypted device storage first, then enroll biometric unlock.",
  "settings.biometricEnabled": "Biometric unlock enabled on this device",
  "settings.biometricNotEnabled": "Biometric unlock is not enabled",
  "settings.biometricDisabled": "Biometric unlock disabled \u2014 passphrase-only vault restored",
  "settings.biometricDisableTitle": "Disable biometric unlock?",
  "settings.biometricDisableText": "The vault returns to passphrase-only storage. Your passphrase will be required to unlock from now on.",
  "settings.biometricDisablePromptAction": "disable biometric unlock",
  "settings.enabledEncryptedFirst": "Enable encrypted device storage before enabling biometric unlock",
  "settings.unlockBeforeBiometric": "Unlock the vault before enabling biometric unlock",
  "settings.exportBackupDone": "Backup exported",
  "settings.exportBackupFailed": "Could not export backup",
  "settings.driftCheckFirst": "Enable the time-drift check first",
  "settings.driftCheckDone": "Time check complete \u2014 see the banner if your clock is off",
  // Settings panel — extension popup (popup.html settings-panel)
  "settings.extensionHeading": "Security",
  "settings.extensionEncryptToggle": "Encrypt entries in extension storage",
  "settings.extensionPassphrasePlaceholder": "New passphrase",
  "settings.extensionPassphraseConfirmPlaceholder": "Confirm passphrase",
  "settings.extensionPassphraseGuidance": "This vault is already encrypted. Use Change Passphrase to rotate your extension secret.",
  "settings.extensionSave": "Save Security Settings",
  "settings.extensionBiometricEnrolled": "Biometric unlock is enrolled. Your passphrase remains the recovery method.",
  "settings.extensionBiometricAvailable": "Unlock with your platform authenticator instead of your passphrase.",
  "settings.extensionClosesLocked": "Closing this popup always locks the vault immediately.",
  "settings.extensionStatusEncryptedSaved": "Encrypted extension vault saved",
  "settings.extensionStatusEncryptedGuidance": "Encrypted extension vault saved. Use Change Passphrase to rotate your extension secret.",
  "settings.extensionStatusPlain": "Extension storage is now plain local storage",
  "settings.extensionPassphraseUpdated": "Extension passphrase updated",
  // Change passphrase flow — shared by both platforms
  "settings.changePassphraseTitle": "Change passphrase",
  "settings.currentPassphraseLabel": "Current passphrase",
  "settings.currentPassphrasePlaceholder": "Enter current passphrase",
  "settings.newPassphraseLabel": "New passphrase",
  "settings.newPassphrasePlaceholder": "Use a new strong passphrase",
  "settings.confirmNewPassphraseLabel": "Confirm new passphrase",
  "settings.confirmNewPassphrasePlaceholder": "Repeat new passphrase",
  "settings.updatePassphrase": "Update Passphrase",
  // Danger zone
  "danger.eyebrow": "danger zone",
  "danger.text": "Removes every entry stored on this device. Export a backup first.",
  "danger.clearAll": "Clear All",
  // Backup flow
  "backup.lastExportNever": "Last export: never",
  "backup.lastExportToday": "Last export: today",
  "backup.lastExportOneDay": "Last export: 1 day ago",
  "backup.lastExportDays": "Last export: {days} days ago",
  "backup.lastExportChecksum": " (checksum {hash})",
  "backup.lastExportSuffix": ". A cancelled download cannot be detected \u2014 verify your backup file after exporting.",
  "backup.reminderExtensionNoExport": "No export yet \u2014 back this vault up below.",
  "backup.reminderExtensionOld": "No export in over 30 days \u2014 export a backup below.",
  "backup.reviewEyebrow": "backup review",
  "backup.reviewHeading": "Review backup before import",
  "backup.importModeLabel": "Import mode",
  "backup.importModeMerge": "Merge with existing entries",
  "backup.importModeReplace": "Replace current vault",
  "backup.passphraseLabel": "Backup passphrase",
  "backup.passphrasePlaceholder": "Required for encrypted backups",
  "backup.importButton": "Import Backup",
  "backup.importDone": "Backup imported",
  "backup.importCancelled": "Backup import cancelled",
  "backup.reviewVerified": "Backup checksum verified. Choose merge to keep existing entries or replace to overwrite the vault.",
  "backup.reviewVerifiedKeyed": "Backup checksum verified with keyed authenticity. Choose merge to keep existing entries or replace to overwrite the vault.",
  "backup.reviewLegacy": "Legacy backup detected. Import is supported, but integrity could not be verified.",
  "backup.reviewNoMac": "Encrypted backup without keyed authenticity (v2 or earlier). It imports, but the file's origin could not be verified.",
  "backup.legacyStatus": "Legacy backup detected. Importing without checksum verification.",
  "backup.passphrasePrompt": "Backup is encrypted. Enter the backup passphrase:",
  "backup.importCancelledNoPassphrase": "Backup import cancelled",
  "backup.macFailed": "Backup authenticity check failed \u2014 the file was modified or this is not its passphrase",
  "backup.fileNotJson": "Backup file is not valid JSON",
  "backup.integrityVerified": "Integrity: verified checksum",
  "backup.integrityVerifiedKeyed": "Integrity: verified checksum (keyed)",
  "backup.integrityLegacy": "Integrity: legacy backup",
  "backup.encryptedYes": "Encrypted: yes",
  "backup.encryptedNo": "Encrypted: no",
  "backup.schemaLine": "Schema: v{version}",
  "backup.createdLine": "Created: {date}",
  "backup.incomingItems": "Incoming items: {count}",
  "backup.vaultSize": "Current vault size: {count}",
  "backup.invalidSkipped": "Review: {count} invalid item{plural} skipped before import",
  "backup.mergeSummary": "Merge: {new} new, {duplicates} duplicate{plural} skipped",
  // Edit entry dialog
  "edit.eyebrow": "edit entry",
  "edit.heading": "Edit vault entry",
  "edit.headingShort": "Edit Entry",
  "edit.labelField": "Label",
  "edit.secretField": "Secret",
  "edit.tagsField": "Tags",
  "edit.counterField": "HOTP counter",
  "edit.algorithmField": "Algorithm",
  "edit.digitsField": "Digits",
  "edit.periodField": "Period",
  "edit.save": "Save Changes",
  "edit.saveShort": "Save",
  "edit.noLongerExists": "Entry no longer exists",
  "edit.duplicate": "Another entry already uses this secret, digits, and period",
  "edit.digitsOption": "{digits} digits",
  "edit.digits6": "6 digits",
  "edit.digits8": "8 digits",
  // Confirm dialogs
  "confirm.eyebrow": "confirm destructive action",
  "confirm.defaultTitle": "Are you sure?",
  "confirm.defaultMessage": "This action cannot be undone.",
  "confirm.removeTitle": "Remove this entry?",
  "confirm.removeText": 'This will remove "{label}" from your vault. You can undo for 10 seconds.',
  "confirm.clearAllTitle": "Clear all entries?",
  "confirm.clearAllText": "This will permanently remove all {count} entr{plural} from your vault. This action cannot be undone.",
  "confirm.bulkRemoveTitle": "Remove selected entries?",
  "confirm.bulkRemoveText": "This will remove {count} selected entr{plural} from your vault. You can undo for 10 seconds.",
  "confirm.replaceVaultTitle": "Replace entire vault?",
  "confirm.replaceVaultText": "This will delete all {count} existing entr{plural} and replace them with the backup contents. This action cannot be undone.",
  // QR export dialog
  "qr.eyebrow": "export entry",
  "qr.heading": "Entry QR code",
  "qr.hint": "Scan with another authenticator app to move this entry. Anyone who scans this code can add your secret \u2014 keep it private.",
  "qr.canvasLabel": "OTPauth QR code",
  "qr.copyUri": "Copy URI",
  "qr.downloadPng": "Download PNG",
  "qr.renderFailed": "Could not render the QR code",
  "qr.copiedUri": "otpauth URI copied",
  // Extension popup surfaces
  "ext.eyebrow": "extension",
  "ext.brand": "OTP Vault",
  "ext.subtitle": "Fast codes from your toolbar.",
  "ext.addEntryHeading": "Add Entry",
  "ext.show": "Show",
  "ext.hide": "Hide",
  "ext.labelPlaceholder": "GitHub:user@example.com",
  "ext.secretPlaceholder": "Base32 secret",
  "ext.tagsPlaceholder": "Tags: work, infra",
  "ext.totpOption": "TOTP (timed)",
  "ext.hotpOption": "HOTP (counter)",
  "ext.qrFile": "QR File",
  "ext.pasteUri": "Paste URI",
  "ext.pasteGa": "Paste GA Export",
  "ext.addEntry": "Add Entry",
  "ext.lock": "Lock",
  "ext.searchPlaceholder": "Search issuer or account",
  "ext.sortAz": "A-Z",
  "ext.sortManual": "Manual",
  "ext.sortNewest": "Newest",
  "ext.sortFastest": "Fastest timer",
  "ext.locked": "Vault is locked. Unlock to view and use your codes.",
  "ext.noEntries": "No entries yet. Add one, import a QR file, or paste an otpauth URI.",
  "ext.historyHeading": "Copy History",
  "ext.historyEmpty": "Copied OTPs will appear here.",
  "ext.copiedIssuer": "Copied {issuer} code",
  "ext.importedQr": "Imported QR entry",
  "ext.importedUri": "Imported URI from clipboard",
  "ext.clipboardDenied": "Clipboard permission denied. Copy the URI into the secret field instead.",
  "ext.clipboardDeniedGa": "Clipboard permission denied. Copy the export URI and try again.",
  "ext.noClipboardUri": "Clipboard does not contain a valid OTP URI",
  "ext.noClipboardGa": "Clipboard does not contain a Google Authenticator export",
  "ext.imported": "Google Authenticator entries imported",
  "ext.removedEntry": "Removed entry",
  "ext.removeConfirm": 'Remove "{label}" from the extension vault? You can undo for 10 minutes by reopening the popup.',
  "ext.removeHeading": "Remove Entry",
  "ext.cannotBeUndone": "This action cannot be undone.",
  "ext.undoOfferOne": "An entry was deleted before this popup closed. Undo?",
  "ext.undoOfferMany": "{count} entries were deleted before this popup closed. Undo?",
  "ext.undoDelete": "Undo delete",
  "ext.undoRemovedOne": "Entry removed",
  "ext.undoRemovedMany": "{count} entries removed \u2014 reopening this popup offers Undo for 10 minutes",
  "ext.undoNothing": "Nothing to undo \u2014 those entries already exist again",
  "ext.importHeading": "Import entries",
  "ext.importApps": "Aegis / 2FAS",
  "ext.importAppsStatus": "{source}: {count} entr{plural} found.",
  "ext.importAppsSkipped": " {count} duplicate{plural} pre-unchecked.",
  "ext.importAppsInvalid": " {count} could not be mapped.",
  "ext.alreadyInVaultSuffix": " (already in vault)",
  "ext.biometricUnlockFailed": "Biometric unlock failed \u2014 use your passphrase",
  "ext.noBiometricEnrolled": "No biometric unlock is enrolled on this device",
  "ext.biometricUnavailable": "Biometric unlock is no longer available \u2014 use your passphrase",
  "ext.unlocked": "Encrypted extension unlocked",
  "ext.encryptionRequiresUnlock": "Unlock extension vault before saving encrypted entries",
  "ext.lockNeedsEncryption": "Enable encrypted storage first",
  "ext.enrollNeedsEncryption": "Enable encrypted storage before enabling biometric unlock",
  "ext.enrollNeedsUnlock": "Unlock the extension vault before enabling biometric unlock",
  "ext.changePassphraseNeedsEncryption": "Enable encrypted storage before changing the extension passphrase",
  "ext.exportNeedsUnlock": "Unlock the extension vault before exporting an encrypted backup",
  "ext.passphrasePromptAction": "Enter your vault passphrase to {action}:",
  "ext.actionExportBackup": "export a backup",
  "ext.actionDisableBiometric": "disable biometric unlock",
  "ext.actionChangePassphrase": "change the extension passphrase",
  "ext.counterSaveFailed": "Counter save failed \u2014 the next code may repeat. Edit the entry to set the counter manually.",
  "ext.tooManyAttempts": "Too many failed attempts \u2014 unlock available in {seconds}s",
  "ext.lockedForSuffix": " Locked for {seconds}s.",
  "ext.incorrectPassphrase": "Incorrect passphrase or unreadable encrypted data",
  "ext.qrNeedsBarcodeDetector": "QR file import requires Chrome BarcodeDetector support",
  "ext.qrNotDetected": "Could not detect a QR code in that file",
  "ext.qrNoOtpUri": "QR code was detected but does not contain a valid OTP URI",
  "ext.accountExists": "This account already exists",
  "ext.hotpCounterBadge": "#{counter}",
  "ext.secondsBadge": "{seconds}s",
  "ext.globalTimerLabel": "OTP refresh timer",
  // Passphrase re-entry prompts (web app)
  "vault.passphrasePrompt": "Enter your vault passphrase to {action}:",
  "vault.passphraseRequired": "Vault passphrase required for this action",
  "vault.actionExportBackup": "export a backup",
  "vault.actionImportBackup": "import a backup",
  "vault.actionDisableBiometric": "disable biometric unlock",
  "vault.actionChangePassphrase": "change the vault passphrase",
  "vault.staleTab": "Vault changed in another tab \u2014 reload this tab to make changes",
  "vault.needsUnlockToSave": "Unlock or set a passphrase before saving encrypted entries",
  "vault.needsPassphraseToEncrypt": "Enter a passphrase to enable encryption",
  "vault.confirmationMismatch": "Passphrase confirmation does not match",
  "vault.currentIncorrect": "Current passphrase is incorrect",
  "vault.changeNeedsEncryption": "Enable encrypted device storage before changing the vault passphrase",
  "vault.hotpSaveFailed": "Counter save failed \u2014 the next code may repeat. Use Edit on this entry to set the counter manually.",
  "vault.accountExists": "This account already exists",
  "vault.tooManyAttempts": "Too many failed attempts \u2014 unlock available in {seconds}s",
  "vault.lockedForSuffix": " Locked for {seconds}s.",
  "vault.noNewEntries": "No new entries found from {source}{details}",
  "vault.noImportable": "No importable entries found in the {source} export{details}",
  "vault.noEntriesToClear": "No entries to clear",
  "vault.allCleared": "All entries cleared",
  "vault.tagsApplied": "Tags applied to selected entries",
  "vault.tagsRequired": "Enter at least one tag for the selected entries",
  "vault.selectedRemoved": "Selected entries removed",
  "vault.bulkRemoveFailed": "Could not remove selected entries",
  "vault.reorderFailed": "Could not reorder entries",
  "vault.reorderEntryFailed": "Could not reorder entry",
  "vault.copyFailedShort": "Could not copy OTP to clipboard",
  "vault.removeFailed": "Could not remove entry",
  "vault.updateFailed": "Could not update entry",
  "vault.addFailed": "Could not add entry",
  "vault.duplicatesSkipped": "{count} duplicate{plural} skipped",
  "vault.invalidIgnored": "{count} invalid URI{plural} ignored",
  "vault.biometricEnrollmentFailed": "Could not enable biometric unlock",
  "vault.biometricDisenrollFailed": "Could not disable biometric unlock",
  "vault.pinFailed": "Could not update entry order",
  "vault.needsUnlockToExport": "Unlock the vault before exporting an encrypted backup",
  "vault.clearFailed": "Could not clear entries",
  "import.gaFailed": "Could not import the Google Authenticator export",
  "import.uriImported": "{source}: account imported",
  "import.qrNotDetectedImage": "Could not detect a QR code in that image",
  "import.qrUrlDownloadFailed": "Could not download QR image URL",
  "import.commitFailed": "Could not import entries",
  "import.fileTooLarge": "Import file exceeds the 8 MB limit",
  "import.mapFailed": "An entry could not be mapped",
  "backup.lastExportShortSuffix": ". A cancelled download cannot be detected.",
  "ext.qrImportFailed": "Could not import QR file",
  "ext.uriImportFailed": "Could not import URI",
  "settings.extensionSaveFailed": "Could not save security settings",
  "settings.updateFailed": "Could not update passphrase",
  "ext.envelopeMissing": "Biometric vault envelope is missing \u2014 unlock with your passphrase to restore it",
  // Passphrase strength (mapped from lib/vault.js assessment labels)
  "strength.veryWeak": "Very weak",
  "strength.weak": "Weak",
  "strength.fair": "Fair",
  "strength.good": "Good",
  "strength.strong": "Strong",
  "strength.enterPassphrase": "Enter a passphrase",
  "strength.avoidCommon": "Avoid common words and patterns",
  "strength.useTwelve": "Use at least 12 characters for a stronger passphrase"
};
var vi = {
  "toast.vaultTitle": "Kho m\xE3",
  "toast.importTitle": "Nh\u1EADp",
  "toast.settingsTitle": "C\xE0i \u0111\u1EB7t",
  "toast.hotpCounterTitle": "B\u1ED9 \u0111\u1EBFm HOTP",
  "toast.copyFailed": "Kh\xF4ng th\u1EC3 sao ch\xE9p m\xE3 OTP",
  "unlock.eyebrow": "tr\u1EA1ng th\xE1i kho",
  "unlock.title": "Kho m\xE3 \u0111\xE3 kh\xF3a tr\xEAn thi\u1EBFt b\u1ECB n\xE0y",
  "unlock.helper": "Nh\u1EADp passphrase \u0111\u1EC3 m\u1EDF kh\xF3a v\xE0 \u0111\u1ECDc c\xE1c m\xE3 \u0111\xE3 m\xE3 h\xF3a tr\xEAn m\xE1y.",
  "unlock.passphrasePlaceholder": "Nh\u1EADp passphrase c\u1EE7a kho",
  "unlock.button": "M\u1EDF kh\xF3a kho m\xE3",
  "unlock.biometricButton": "M\u1EDF b\u1EB1ng sinh tr\u1EAFc h\u1ECDc",
  "unlock.statusSuccess": "\u0110\xE3 m\u1EDF kh\xF3a kho m\xE3",
  "unlock.statusBiometricSuccess": "\u0110\xE3 m\u1EDF kh\xF3a b\u1EB1ng sinh tr\u1EAFc h\u1ECDc",
  "unlock.statusFailed": "Passphrase sai ho\u1EB7c d\u1EEF li\u1EC7u m\xE3 h\xF3a kh\xF4ng \u0111\u1ECDc \u0111\u01B0\u1EE3c",
  "unlock.extensionTitle": "Kho c\u1EE7a ti\u1EC7n \xEDch",
  "unlock.extensionPassphrasePlaceholder": "Passphrase \u0111\u1EC3 m\u1EDF kho m\xE3 h\xF3a",
  "unlock.extensionButton": "M\u1EDF kh\xF3a",
  "unlock.extensionStatusSuccess": "\u0110\xE3 m\u1EDF kh\xF3a kho m\xE3",
  "common.cancel": "H\u1EE7y",
  "common.close": "\u0110\xF3ng",
  "common.copy": "Sao ch\xE9p",
  "common.copied": "\u0110\xE3 sao ch\xE9p",
  "common.undo": "Ho\xE0n t\xE1c",
  "common.confirm": "X\xE1c nh\u1EADn",
  "common.import": "Nh\u1EADp",
  "common.save": "L\u01B0u",
  "common.remove": "X\xF3a",
  "common.edit": "S\u1EEDa",
  "common.dismiss": "B\u1ECF qua",
  "common.reload": "T\u1EA3i l\u1EA1i",
  "entries.headingLocked": "Kho \u0111\xE3 kh\xF3a",
  "entries.headingCurrent": "M\xE3 hi\u1EC7n t\u1EA1i",
  "entries.copy": "Sao ch\xE9p",
  "entries.copied": "\u0110\xE3 sao ch\xE9p",
  "entries.reveal": "Hi\u1EC7n",
  "entries.hide": "\u1EA8n",
  "entries.pin": "Ghim",
  "entries.unpin": "B\u1ECF ghim",
  "entries.up": "L\xEAn",
  "entries.down": "Xu\u1ED1ng",
  "entries.qr": "QR",
  "entries.invalidSecret": "Secret kh\xF4ng h\u1EE3p l\u1EC7",
  "entries.invalidShort": "L\u1ED7i",
  "entries.counterLeft": "b\u1ED9 \u0111\u1EBFm #{counter}",
  "entries.secondsLeft": "c\xF2n {seconds}s",
  "entries.meta": "{digits} ch\u1EEF s\u1ED1 \u2022 {period}s",
  "entries.pinToggled": "\u0110\xE3 c\u1EADp nh\u1EADt th\u1EE9 t\u1EF1 m\u1EE5c",
  "entries.removed": "\u0110\xE3 x\xF3a m\u1EE5c",
  "entries.updated": "\u0110\xE3 c\u1EADp nh\u1EADt m\u1EE5c",
  "entries.manualOrderUpdated": "\u0110\xE3 c\u1EADp nh\u1EADt th\u1EE9 t\u1EF1 th\u1EE7 c\xF4ng",
  "entries.groupAll": "T\u1EA5t c\u1EA3 m\u1EE5c",
  "entries.groupUntagged": "Ch\u01B0a g\u1EAFn nh\xE3n",
  "entries.select": "Ch\u1ECDn m\u1EE5c",
  "entries.reorder": "S\u1EAFp x\u1EBFp l\u1EA1i m\u1EE5c",
  "entries.dragToReorder": "K\xE9o \u0111\u1EC3 s\u1EAFp x\u1EBFp",
  "empty.heading": "Kho s\u1EB5n s\xE0ng cho l\u1EA7n nh\u1EADp \u0111\u1EA7u ti\xEAn",
  "empty.kicker": "kho m\xE3",
  "empty.headingLocked": "Kho \u0111ang kh\xF3a",
  "empty.headingNoMatch": "Kh\xF4ng c\xF3 m\u1EE5c kh\u1EDBp",
  "empty.locked": "Kho \u0111ang kh\xF3a. M\u1EDF kh\xF3a \u0111\u1EC3 xem m\xE3 c\u1EE7a b\u1EA1n.",
  "empty.noEntries": "Ch\u01B0a c\xF3 m\u1EE5c n\xE0o. H\xE3y nh\u1EADp URI, qu\xE9t QR, ho\u1EB7c th\xEAm th\u1EE7 c\xF4ng.",
  "empty.noMatch": "Thay \u0111\u1ED5i t\u1EEB kh\xF3a t\xECm ki\u1EBFm ho\u1EB7c x\xF3a b\u1ED9 l\u1ECDc \u0111\u1EC3 th\u1EA5y c\xE1c m\u1EE5c.",
  "empty.addFirst": "Th\xEAm m\u1EE5c \u0111\u1EA7u ti\xEAn",
  "empty.pasteUri": "D\xE1n URI",
  "empty.scanQr": "Qu\xE9t m\xE3 QR",
  "empty.step1Title": "1. Nh\u1EADp ho\u1EB7c g\xF5",
  "empty.step1Text": "D\xF9ng Base32, URI, clipboard, \u1EA3nh QR, ho\u1EB7c camera.",
  "empty.step2Title": "2. Xem l\u1EA1i v\xE0 g\u1EAFn nh\xE3n",
  "empty.step2Text": "Ph\xE1t hi\u1EC7n tr\xF9ng l\u1EB7p s\u1EDBm v\xE0 s\u1EAFp x\u1EBFp kho theo d\u1EF1 \xE1n ho\u1EB7c thi\u1EBFt b\u1ECB.",
  "empty.step3Title": "3. B\u1EA3o v\u1EC7 thi\u1EBFt b\u1ECB n\xE0y",
  "empty.step3Text": "Ch\u1EC9 b\u1EADt l\u01B0u tr\u1EEF khi c\u1EA7n, sau \u0111\xF3 th\xEAm m\xE3 h\xF3a v\xE0 sao l\u01B0u.",
  "topbar.searchPlaceholder": "T\xECm theo nh\xE0 cung c\u1EA5p, t\xE0i kho\u1EA3n ho\u1EB7c nh\xE3n",
  "topbar.searchLabel": "T\xECm m\u1EE5c",
  "topbar.copyHistory": "L\u1ECBch s\u1EED sao ch\xE9p",
  "topbar.settings": "C\xE0i \u0111\u1EB7t kho m\xE3",
  "topbar.install": "C\xE0i \u1EE9ng d\u1EE5ng",
  "topbar.lock": "Kh\xF3a kho m\xE3",
  "topbar.add": "+ Th\xEAm",
  "workspace.summaryAccounts": "T\xE0i kho\u1EA3n",
  "workspace.summaryPinned": "\u0110\xE3 ghim",
  "workspace.summaryGroups": "Nh\xF3m",
  "workspace.summaryStorage": "L\u01B0u tr\u1EEF",
  "workspace.storageEncrypted": "M\xE3 h\xF3a",
  "workspace.storageDevice": "Thi\u1EBFt b\u1ECB",
  "workspace.storageSession": "Phi\xEAn",
  "workspace.storageLocked": " (\u0110\xE3 kh\xF3a)",
  "workspace.online": "Tr\u1EF1c tuy\u1EBFn",
  "workspace.offlineReady": "S\u1EB5n s\xE0ng ngo\u1EA1i tuy\u1EBFn",
  "workspace.sortLabel": "S\u1EAFp x\u1EBFp",
  "workspace.groupLabel": "Nh\xF3m theo",
  "workspace.sortPinnedAlpha": "Ghim + A-Z",
  "workspace.sortManual": "Th\u1EE9 t\u1EF1 th\u1EE7 c\xF4ng",
  "workspace.sortRecent": "M\u1EDBi nh\u1EA5t tr\u01B0\u1EDBc",
  "workspace.sortPeriod": "H\u1EB9n gi\u1EDD nhanh nh\u1EA5t tr\u01B0\u1EDBc",
  "workspace.groupNone": "Kh\xF4ng nh\xF3m",
  "workspace.groupIssuer": "Nh\xE0 cung c\u1EA5p",
  "workspace.groupTag": "Nh\xE3n \u0111\u1EA7u ti\xEAn",
  "workspace.selectedCount": "\u0110\xE3 ch\u1ECDn {count}",
  "workspace.bulkAddTagPlaceholder": "Th\xEAm nh\xE3n cho m\u1EE5c \u0111\xE3 ch\u1ECDn",
  "workspace.bulkApplyTag": "\xC1p d\u1EE5ng nh\xE3n",
  "workspace.bulkRemove": "X\xF3a m\u1EE5c \u0111\xE3 ch\u1ECDn",
  "banner.stale": "Kho m\xE3 \u0111\xE3 thay \u0111\u1ED5i \u1EDF tab kh\xE1c. Tab n\xE0y ch\u1EC9 \u0111\u1ECDc \u2014 h\xE3y t\u1EA3i l\u1EA1i \u0111\u1EC3 nh\u1EADn d\u1EEF li\u1EC7u m\u1EDBi nh\u1EA5t.",
  "banner.backupReminder": "\u0110\xE3 h\u01A1n 30 ng\xE0y ch\u01B0a xu\u1EA5t kho m\xE3 \u2014 h\xE3y xu\u1EA5t b\u1EA3n sao l\u01B0u trong ph\u1EA7n c\xE0i \u0111\u1EB7t b\xEAn d\u01B0\u1EDBi.",
  "banner.driftPrefix": "\u0110\u1ED3ng h\u1ED3 thi\u1EBFt b\u1ECB l\u1EC7ch",
  "banner.driftSuffix": " \u2014 m\xE3 TOTP c\xF3 th\u1EC3 b\u1ECB t\u1EEB ch\u1ED1i. H\xE3y ch\u1EC9nh \u0111\u1ED3ng h\u1ED3 h\u1EC7 th\u1ED1ng.",
  "banner.driftSuffixExtension": " \u2014 m\xE3 TOTP c\xF3 th\u1EC3 b\u1ECB t\u1EEB ch\u1ED1i.",
  "privacy.eyebrow": "c\u1EA3nh b\xE1o l\u01B0u tr\u1EEF",
  "privacy.title": "Tr\u01B0\u1EDBc khi b\u1EADt l\u01B0u tr\u1EEF tr\xEAn thi\u1EBFt b\u1ECB",
  "privacy.text": "Secret 2FA c\u1EE7a b\u1EA1n s\u1EBD \u0111\u01B0\u1EE3c l\u01B0u trong b\u1ED9 nh\u1EDB tr\xECnh duy\u1EC7t tr\xEAn thi\u1EBFt b\u1ECB n\xE0y. H\xE3y d\xF9ng l\u01B0u tr\u1EEF m\xE3 h\xF3a v\xE0 ch\u1EC9 b\u1EADt tr\xEAn ph\u1EA7n c\u1EE9ng \u0111\xE1ng tin c\u1EADy.",
  "privacy.accept": "T\xF4i hi\u1EC3u",
  "add.eyebrow": "\u0111i\u1EC1u khi\u1EC3n kho m\xE3",
  "add.heading": "Th\xEAm & nh\u1EADp m\u1EE5c",
  "add.tabManual": "Th\u1EE7 c\xF4ng",
  "add.tabPaste": "D\xE1n",
  "add.tabQr": "QR",
  "add.tabCamera": "Camera",
  "add.panelManual": "Th\xEAm m\u1EE5c th\u1EE7 c\xF4ng",
  "add.panelPaste": "D\xE1n URI",
  "add.panelQrImage": "Nh\u1EADp t\u1EEB \u1EA3nh QR",
  "add.panelCamera": "Nh\u1EADp qua camera",
  "add.secretLabel": "Secret Base32",
  "add.labelLabel": "Nh\xE3n (kh\xF4ng b\u1EAFt bu\u1ED9c)",
  "add.tagsLabel": "Nh\xE3n",
  "add.typeLabel": "Ki\u1EC3u",
  "add.counterLabel": "B\u1ED9 \u0111\u1EBFm",
  "add.algorithmLabel": "Thu\u1EADt to\xE1n",
  "add.digitsLabel": "S\u1ED1 ch\u1EEF s\u1ED1",
  "add.periodLabel": "Chu k\u1EF3 (gi\xE2y)",
  "add.saveEntry": "L\u01B0u m\u1EE5c",
  "add.pasteUrisLabel": "D\xE1n m\u1ED9t ho\u1EB7c nhi\u1EC1u URI `otpauth://`",
  "add.pastePlaceholder": "D\xE1n m\u1ED9t ho\u1EB7c nhi\u1EC1u OTP URI v\xE0o \u0111\xE2y. Kho s\u1EBD xem tr\u01B0\u1EDBc c\xE1c URI h\u1EE3p l\u1EC7 tr\u01B0\u1EDBc khi nh\u1EADp.",
  "add.importUri": "Nh\u1EADp URI otpauth://",
  "add.importGa": "Nh\u1EADp Google Authenticator",
  "add.importClipboard": "Nh\u1EADp t\u1EEB clipboard",
  "add.importApps": "Nh\u1EADp Aegis / 2FAS",
  "add.qrFileLabel": "T\u1EC7p \u1EA3nh QR",
  "add.qrFileChoose": "Ch\u1ECDn t\u1EC7p \u1EA3nh\u2026",
  "add.qrUrlLabel": "URL \u1EA3nh QR",
  "add.qrUrlPlaceholder": "https://example.com/qr.png",
  "add.cameraHint": "M\xE3 qu\xE9t ch\u1EC9 \u0111\u01B0\u1EE3c ch\u1EA5p nh\u1EADn sau khi l\u1EB7p l\u1EA1i qua hai khung h\xECnh, gi\u1EA3m kh\u1EA3 n\u0103ng nh\u1EADn nh\u1EA7m.",
  "add.startCamera": "B\u1EADt camera",
  "add.stopCamera": "D\u1EEBng",
  "add.entryAdded": "\u0110\xE3 th\xEAm m\u1EE5c",
  "import.readingClipboard": "\u0110ang \u0111\u1ECDc clipboard...",
  "import.readingQrFile": "\u0110ang \u0111\u1ECDc t\u1EC7p QR...",
  "import.fetchingQrUrl": "\u0110ang t\u1EA3i \u1EA3nh QR t\u1EEB URL...",
  "import.qrUrlRequired": "Vui l\xF2ng nh\u1EADp URL \u1EA3nh QR",
  "import.invalidUri": "URI kh\xF4ng h\u1EE3p l\u1EC7",
  "import.noValidUri": "Kh\xF4ng t\xECm th\u1EA5y URI otpauth:// h\u1EE3p l\u1EC7",
  "import.pasteGaFirst": "D\xE1n n\u1ED9i dung xu\u1EA5t t\u1EEB Google Authenticator (d\xF2ng otpauth-migration:// ho\u1EB7c URI) tr\u01B0\u1EDBc",
  "import.noGaFound": "Kh\xF4ng t\xECm th\u1EA5y b\u1EA3n xu\u1EA5t Google Authenticator trong n\u1ED9i dung \u0111\xE3 d\xE1n",
  "import.decodingGa": "\u0110ang gi\u1EA3i m\xE3 b\u1EA3n xu\u1EA5t Google Authenticator...",
  "import.noClipboardUri": "Clipboard kh\xF4ng ch\u1EE9a OTP URI ho\u1EB7c \u1EA3nh QR h\u1EE3p l\u1EC7",
  "import.noValidOtpUriInQr": "Ph\xE1t hi\u1EC7n m\xE3 QR nh\u01B0ng kh\xF4ng ch\u1EE9a OTP URI h\u1EE3p l\u1EC7",
  "import.cameraReady": "Camera \u0111\xE3 s\u1EB5n s\xE0ng. Gi\u1EEF m\xE3 QR tr\u01B0\u1EDBc camera.",
  "import.cameraStopped": "\u0110\xE3 d\u1EEBng camera",
  "import.startingCamera": "\u0110ang b\u1EADt camera...",
  "import.scanConfirming": "Ph\xE1t hi\u1EC7n QR OTP ti\u1EC1m n\u0103ng. \u0110ang x\xE1c nh\u1EADn b\u1EB1ng khung h\xECnh kh\xE1c...",
  "import.scanProgress": "\u0110\xE3 qu\xE9t {done}/{total} m\xE3 QR...",
  "import.scanComplete": "\u0110\xE3 qu\xE9t t\u1EA5t c\u1EA3 m\xE3 QR.",
  "import.scanMixedBatches": "Ph\xE1t hi\u1EC7n m\xE3 QR t\u1EEB c\xE1c l\u1EA7n xu\u1EA5t kh\xE1c nhau \u2014 h\xE3y qu\xE9t l\u1EA1i v\u1EDBi m\u1ED9t l\u1EA7n xu\u1EA5t.",
  "import.fileReadFailed": "Kh\xF4ng th\u1EC3 nh\u1EADp t\u1EC7p QR",
  "import.urlReadFailed": "Kh\xF4ng th\u1EC3 nh\u1EADp t\u1EEB URL",
  "import.clipboardFailed": "Kh\xF4ng th\u1EC3 nh\u1EADp t\u1EEB clipboard",
  "import.previewTitle": "Xem l\u1EA1i {count} m\u1EE5c d\u1EF1 ki\u1EBFn",
  "import.previewHeading": "Xem l\u1EA1i m\u1EE5c nh\u1EADp d\u1EF1 ki\u1EBFn",
  "import.previewHint": "Kho ch\u1EC9 nh\u1EADp c\xE1c m\u1EE5c v\u01B0\u1EE3t qua ki\u1EC3m tra URI nghi\xEAm ng\u1EB7t.",
  "import.previewStatus": "{source}: ch\u1EC9 hi\u1EC3n th\u1ECB c\xE1c m\u1EE5c h\u1EE3p l\u1EC7, kh\xF4ng tr\xF9ng l\u1EB7p b\xEAn d\u01B0\u1EDBi.",
  "import.previewSkipped": " \u0110\xE3 b\u1ECF qua {count} m\u1EE5c tr\xF9ng l\u1EB7p.",
  "import.previewInvalid": " \u0110\xE3 b\u1ECF qua {count} m\u1EE5c kh\xF4ng h\u1EE3p l\u1EC7.",
  "import.alreadyInVault": "\u0110\xE3 c\xF3 trong kho",
  "import.includeEntry": "Nh\u1EADp m\u1EE5c n\xE0y",
  "import.previewLabelField": "Nh\xE3n",
  "import.previewTagsField": "Nh\xE3n",
  "import.previewTagsPlaceholder": "d\u1EF1 \xE1n, kh\xF3a-ph\u1EA7n-c\u1EE9ng",
  "import.applyTagsLabel": "G\u1EAFn nh\xE3n cho c\xE1c m\u1EE5c nh\u1EADp",
  "import.importEntries": "Nh\u1EADp c\xE1c m\u1EE5c",
  "import.selectAtLeastOne": "H\xE3y ch\u1ECDn \xEDt nh\u1EA5t m\u1ED9t m\u1EE5c \u0111\u1EC3 nh\u1EADp",
  "import.importedOne": "{source}: \u0111\xE3 nh\u1EADp 1 m\u1EE5c",
  "import.importedMany": "{source}: \u0111\xE3 nh\u1EADp {count} m\u1EE5c",
  "import.restoredOne": "\u0110\xE3 kh\xF4i ph\u1EE5c 1 m\u1EE5c",
  "import.restoredMany": "\u0110\xE3 kh\xF4i ph\u1EE5c {count} m\u1EE5c",
  "import.nothingToUndo": "Kh\xF4ng c\xF3 g\xEC \u0111\u1EC3 ho\xE0n t\xE1c \u2014 c\xE1c m\u1EE5c \u0111\xF3 \u0111\xE3 t\u1ED3n t\u1EA1i l\u1EA1i",
  "import.appsFileFailed": "Kh\xF4ng th\u1EC3 nh\u1EADp t\u1EC7p Aegis / 2FAS",
  "import.appsReading": "\u0110ang gi\u1EA3i m\xE3 b\u1EA3n xu\u1EA5t Aegis / 2FAS...",
  "undo.entryRemovedOne": "\u0110\xE3 x\xF3a m\u1EE5c",
  "undo.entryRemovedMany": "\u0110\xE3 x\xF3a {count} m\u1EE5c",
  "history.eyebrow": "ho\u1EA1t \u0111\u1ED9ng g\u1EA7n \u0111\xE2y",
  "history.heading": "L\u1ECBch s\u1EED sao ch\xE9p",
  "history.empty": "Ch\u01B0a c\xF3 m\xE3 n\xE0o \u0111\u01B0\u1EE3c sao ch\xE9p. V\xE0i m\xE3 OTP g\u1EA7n nh\u1EA5t s\u1EBD hi\u1EC7n \u1EDF \u0111\xE2y \u0111\u1EC3 tra nhanh.",
  "settings.eyebrow": "quy\u1EC1n ri\xEAng t\u01B0",
  "settings.heading": "\u0110i\u1EC1u khi\u1EC3n thi\u1EBFt b\u1ECB & sao l\u01B0u",
  "settings.persistToggle": "Ghi nh\u1EDB c\xE1c m\u1EE5c tr\xEAn thi\u1EBFt b\u1ECB n\xE0y",
  "settings.encryptToggle": "M\xE3 h\xF3a c\xE1c m\u1EE5c \u0111\xE3 l\u01B0u b\u1EB1ng passphrase",
  "settings.unlockOnLoadToggle": "Y\xEAu c\u1EA7u m\u1EDF kh\xF3a khi m\u1EDF \u1EE9ng d\u1EE5ng",
  "settings.blurCodesToggle": "L\xE0m m\u1EDD m\xE3 OTP cho \u0111\u1EBFn khi di chu\u1ED9t ho\u1EB7c focus",
  "settings.screenshotSafeToggle": "Ch\u1EBF \u0111\u1ED9 an to\xE0n ch\u1EE5p m\xE0n h\xECnh \u1EA9n m\xE3 cho \u0111\u1EBFn khi hi\u1EC7n th\u1EE7 c\xF4ng",
  "settings.clearClipboardToggle": "X\xF3a clipboard 30 gi\xE2y sau khi sao ch\xE9p",
  "settings.autoLockLabel": "T\u1EF1 \u0111\u1ED9ng kh\xF3a (kho m\xE3 h\xF3a)",
  "settings.autoLockAfter": "Sau {minutes} ph\xFAt kh\xF4ng ho\u1EA1t \u0111\u1ED9ng",
  "settings.autoLockOffOption": "T\u1EAFt",
  "settings.languageLabel": "Ng\xF4n ng\u1EEF",
  "settings.languageSystem": "Theo h\u1EC7 th\u1ED1ng",
  "settings.passphraseLabel": "Passphrase c\u1EE7a kho",
  "settings.passphrasePlaceholder": "D\xF9ng passphrase m\u1EA1nh",
  "settings.passphraseConfirmLabel": "X\xE1c nh\u1EADn passphrase",
  "settings.passphraseConfirmPlaceholder": "Nh\u1EADp l\u1EA1i passphrase",
  "settings.passphraseGuidance": "Kho n\xE0y \u0111\xE3 \u0111\u01B0\u1EE3c m\xE3 h\xF3a. D\xF9ng \u0110\u1ED5i passphrase \u0111\u1EC3 xoay secret c\u1EE7a kho.",
  "settings.exportBackup": "Xu\u1EA5t b\u1EA3n sao l\u01B0u",
  "settings.importBackup": "Nh\u1EADp b\u1EA3n sao l\u01B0u",
  "settings.changePassphrase": "\u0110\u1ED5i passphrase",
  "settings.checkClockNow": "Ki\u1EC3m tra \u0111\u1ED3ng h\u1ED3 ngay",
  "settings.save": "L\u01B0u c\xE0i \u0111\u1EB7t ri\xEAng t\u01B0",
  "settings.autoLock": "T\u1EF1 \u0111\u1ED9ng kh\xF3a kho sau {minutes} ph\xFAt",
  "settings.autoLockOff": "T\u1EF1 \u0111\u1ED9ng kh\xF3a \u0111ang t\u1EAFt",
  "settings.autoLock5": "Sau 5 ph\xFAt kh\xF4ng ho\u1EA1t \u0111\u1ED9ng",
  "settings.autoLock15": "Sau 15 ph\xFAt kh\xF4ng ho\u1EA1t \u0111\u1ED9ng",
  "settings.autoLock30": "Sau 30 ph\xFAt kh\xF4ng ho\u1EA1t \u0111\u1ED9ng",
  "settings.languageEn": "Ti\u1EBFng Anh",
  "settings.languageVi": "Ti\u1EBFng Vi\u1EC7t",
  "changepass.eyebrow": "passphrase c\u1EE7a kho",
  "import.previewEyebrow": "xem l\u1EA1i m\u1EE5c nh\u1EADp",
  "settings.themeLabel": "Giao di\u1EC7n",
  "settings.themeSystem": "Theo h\u1EC7 th\u1ED1ng",
  "settings.themeLight": "S\xE1ng",
  "settings.themeDark": "T\u1ED1i",
  "settings.driftToggle": "Ki\u1EC3m tra \u0111\u1ED3ng h\u1ED3 thi\u1EBFt b\u1ECB v\u1EDBi gi\u1EDD m\xE1y ch\u1EE7 (c\u1EA7n m\u1EA1ng)",
  "settings.statusEncryptedVaultSaved": "\u0110\xE3 l\u01B0u kho m\xE3 h\xF3a. D\xF9ng \u0110\u1ED5i passphrase \u0111\u1EC3 xoay secret c\u1EE7a kho.",
  "settings.statusEncryptedSaved": "\u0110\xE3 l\u01B0u kho m\xE3 h\xF3a",
  "settings.statusDeviceStorageUpdated": "\u0110\xE3 c\u1EADp nh\u1EADt l\u01B0u tr\u1EEF tr\xEAn thi\u1EBFt b\u1ECB",
  "settings.statusSessionOnly": "C\xE1c m\u1EE5c hi\u1EC7n ch\u1EC9 t\u1ED3n t\u1EA1i trong phi\xEAn",
  "settings.statusImportFailed": "Kh\xF4ng th\u1EC3 nh\u1EADp b\u1EA3n sao l\u01B0u",
  "settings.statusPassphraseUpdated": "\u0110\xE3 c\u1EADp nh\u1EADt passphrase c\u1EE7a kho",
  "settings.statusLockRequiresEncryption": "H\xE3y b\u1EADt l\u01B0u tr\u1EEF m\xE3 h\xF3a \u0111\u1EC3 d\xF9ng kh\xF3a/m\u1EDF kh\xF3a",
  "settings.statusSaveFailed": "Kh\xF4ng th\u1EC3 l\u01B0u c\xE0i \u0111\u1EB7t",
  "settings.statusInstallUnavailable": "Tr\xECnh duy\u1EC7t n\xE0y ch\u01B0a h\u1ED7 tr\u1EE3 l\u1EDDi nh\u1EAFc c\xE0i \u0111\u1EB7t",
  "settings.biometricEyebrow": "m\u1EDF kh\xF3a sinh tr\u1EAFc h\u1ECDc",
  "settings.biometricEnroll": "B\u1EADt m\u1EDF kh\xF3a sinh tr\u1EAFc h\u1ECDc",
  "settings.biometricDisenroll": "T\u1EAFt m\u1EDF kh\xF3a sinh tr\u1EAFc h\u1ECDc",
  "settings.biometricEnrolled": "M\u1EDF kh\xF3a sinh tr\u1EAFc h\u1ECDc \u0111\xE3 \u0111\u01B0\u1EE3c k\xEDch ho\u1EA1t tr\xEAn thi\u1EBFt b\u1ECB n\xE0y. Passphrase v\u1EABn l\xE0 ph\u01B0\u01A1ng \xE1n kh\xF4i ph\u1EE5c.",
  "settings.biometricAvailable": "M\u1EDF kh\xF3a b\u1EB1ng authenticator c\u1EE7a n\u1EC1n t\u1EA3ng thay v\xEC passphrase. Passphrase v\u1EABn gi\u1EEF l\xE0m ph\u01B0\u01A1ng \xE1n kh\xF4i ph\u1EE5c.",
  "settings.biometricNeedsEncryption": "H\xE3y b\u1EADt l\u01B0u tr\u1EEF m\xE3 h\xF3a tr\xEAn thi\u1EBFt b\u1ECB tr\u01B0\u1EDBc, sau \u0111\xF3 k\xEDch ho\u1EA1t sinh tr\u1EAFc h\u1ECDc.",
  "settings.biometricEnabled": "\u0110\xE3 b\u1EADt m\u1EDF kh\xF3a sinh tr\u1EAFc h\u1ECDc tr\xEAn thi\u1EBFt b\u1ECB n\xE0y",
  "settings.biometricNotEnabled": "M\u1EDF kh\xF3a sinh tr\u1EAFc h\u1ECDc ch\u01B0a \u0111\u01B0\u1EE3c b\u1EADt",
  "settings.biometricDisabled": "\u0110\xE3 t\u1EAFt m\u1EDF kh\xF3a sinh tr\u1EAFc h\u1ECDc \u2014 kho quay l\u1EA1i ch\u1EC9 d\xF9ng passphrase",
  "settings.biometricDisableTitle": "T\u1EAFt m\u1EDF kh\xF3a sinh tr\u1EAFc h\u1ECDc?",
  "settings.biometricDisableText": "Kho s\u1EBD quay l\u1EA1i l\u01B0u tr\u1EEF ch\u1EC9 d\xF9ng passphrase. T\u1EEB gi\u1EDD m\u1EDF kh\xF3a s\u1EBD c\u1EA7n passphrase.",
  "settings.biometricDisablePromptAction": "t\u1EAFt m\u1EDF kh\xF3a sinh tr\u1EAFc h\u1ECDc",
  "settings.enabledEncryptedFirst": "H\xE3y b\u1EADt l\u01B0u tr\u1EEF m\xE3 h\xF3a tr\xEAn thi\u1EBFt b\u1ECB tr\u01B0\u1EDBc khi b\u1EADt m\u1EDF kh\xF3a sinh tr\u1EAFc h\u1ECDc",
  "settings.unlockBeforeBiometric": "M\u1EDF kh\xF3a kho tr\u01B0\u1EDBc khi b\u1EADt m\u1EDF kh\xF3a sinh tr\u1EAFc h\u1ECDc",
  "settings.exportBackupDone": "\u0110\xE3 xu\u1EA5t b\u1EA3n sao l\u01B0u",
  "settings.exportBackupFailed": "Kh\xF4ng th\u1EC3 xu\u1EA5t b\u1EA3n sao l\u01B0u",
  "settings.driftCheckFirst": "H\xE3y b\u1EADt ki\u1EC3m tra l\u1EC7ch gi\u1EDD tr\u01B0\u1EDBc",
  "settings.driftCheckDone": "\u0110\xE3 ki\u1EC3m tra gi\u1EDD \u2014 xem banner n\u1EBFu \u0111\u1ED3ng h\u1ED3 b\u1ECB l\u1EC7ch",
  "settings.extensionHeading": "B\u1EA3o m\u1EADt",
  "settings.extensionEncryptToggle": "M\xE3 h\xF3a c\xE1c m\u1EE5c trong b\u1ED9 nh\u1EDB ti\u1EC7n \xEDch",
  "settings.extensionPassphrasePlaceholder": "Passphrase m\u1EDBi",
  "settings.extensionPassphraseConfirmPlaceholder": "X\xE1c nh\u1EADn passphrase",
  "settings.extensionPassphraseGuidance": "Kho n\xE0y \u0111\xE3 \u0111\u01B0\u1EE3c m\xE3 h\xF3a. D\xF9ng \u0110\u1ED5i passphrase \u0111\u1EC3 xoay secret c\u1EE7a ti\u1EC7n \xEDch.",
  "settings.extensionSave": "L\u01B0u c\xE0i \u0111\u1EB7t b\u1EA3o m\u1EADt",
  "settings.extensionBiometricEnrolled": "M\u1EDF kh\xF3a sinh tr\u1EAFc h\u1ECDc \u0111\xE3 \u0111\u01B0\u1EE3c k\xEDch ho\u1EA1t. Passphrase v\u1EABn l\xE0 ph\u01B0\u01A1ng \xE1n kh\xF4i ph\u1EE5c.",
  "settings.extensionBiometricAvailable": "M\u1EDF kh\xF3a b\u1EB1ng authenticator c\u1EE7a n\u1EC1n t\u1EA3ng thay v\xEC passphrase.",
  "settings.extensionClosesLocked": "\u0110\xF3ng popup n\xE0y lu\xF4n kh\xF3a kho ngay l\u1EADp t\u1EE9c.",
  "settings.extensionStatusEncryptedSaved": "\u0110\xE3 l\u01B0u kho m\xE3 h\xF3a c\u1EE7a ti\u1EC7n \xEDch",
  "settings.extensionStatusEncryptedGuidance": "\u0110\xE3 l\u01B0u kho m\xE3 h\xF3a c\u1EE7a ti\u1EC7n \xEDch. D\xF9ng \u0110\u1ED5i passphrase \u0111\u1EC3 xoay secret c\u1EE7a ti\u1EC7n \xEDch.",
  "settings.extensionStatusPlain": "B\u1ED9 nh\u1EDB ti\u1EC7n \xEDch hi\u1EC7n l\xE0 l\u01B0u tr\u1EEF th\u01B0\u1EDDng",
  "settings.extensionPassphraseUpdated": "\u0110\xE3 c\u1EADp nh\u1EADt passphrase c\u1EE7a ti\u1EC7n \xEDch",
  "settings.changePassphraseTitle": "\u0110\u1ED5i passphrase",
  "settings.currentPassphraseLabel": "Passphrase hi\u1EC7n t\u1EA1i",
  "settings.currentPassphrasePlaceholder": "Nh\u1EADp passphrase hi\u1EC7n t\u1EA1i",
  "settings.newPassphraseLabel": "Passphrase m\u1EDBi",
  "settings.newPassphrasePlaceholder": "D\xF9ng passphrase m\u1EDBi m\u1EA1nh",
  "settings.confirmNewPassphraseLabel": "X\xE1c nh\u1EADn passphrase m\u1EDBi",
  "settings.confirmNewPassphrasePlaceholder": "Nh\u1EADp l\u1EA1i passphrase m\u1EDBi",
  "settings.updatePassphrase": "C\u1EADp nh\u1EADt passphrase",
  "danger.eyebrow": "v\xF9ng nguy hi\u1EC3m",
  "danger.text": "X\xF3a m\u1ECDi m\u1EE5c \u0111\xE3 l\u01B0u tr\xEAn thi\u1EBFt b\u1ECB n\xE0y. H\xE3y xu\u1EA5t b\u1EA3n sao l\u01B0u tr\u01B0\u1EDBc.",
  "danger.clearAll": "X\xF3a t\u1EA5t c\u1EA3",
  "backup.lastExportNever": "L\u1EA7n xu\u1EA5t g\u1EA7n nh\u1EA5t: ch\u01B0a bao gi\u1EDD",
  "backup.lastExportToday": "L\u1EA7n xu\u1EA5t g\u1EA7n nh\u1EA5t: h\xF4m nay",
  "backup.lastExportOneDay": "L\u1EA7n xu\u1EA5t g\u1EA7n nh\u1EA5t: 1 ng\xE0y tr\u01B0\u1EDBc",
  "backup.lastExportDays": "L\u1EA7n xu\u1EA5t g\u1EA7n nh\u1EA5t: {days} ng\xE0y tr\u01B0\u1EDBc",
  "backup.lastExportChecksum": " (checksum {hash})",
  "backup.lastExportSuffix": ". Kh\xF4ng th\u1EC3 ph\xE1t hi\u1EC7n l\u01B0\u1EE3t t\u1EA3i b\u1ECB h\u1EE7y \u2014 h\xE3y ki\u1EC3m tra t\u1EC7p sao l\u01B0u sau khi xu\u1EA5t.",
  "backup.reminderExtensionNoExport": "Ch\u01B0a xu\u1EA5t l\u1EA7n n\xE0o \u2014 h\xE3y sao l\u01B0u kho b\xEAn d\u01B0\u1EDBi.",
  "backup.reminderExtensionOld": "\u0110\xE3 h\u01A1n 30 ng\xE0y ch\u01B0a xu\u1EA5t \u2014 h\xE3y xu\u1EA5t b\u1EA3n sao l\u01B0u b\xEAn d\u01B0\u1EDBi.",
  "backup.reviewEyebrow": "xem l\u1EA1i b\u1EA3n sao l\u01B0u",
  "backup.reviewHeading": "Xem l\u1EA1i b\u1EA3n sao l\u01B0u tr\u01B0\u1EDBc khi nh\u1EADp",
  "backup.importModeLabel": "Ch\u1EBF \u0111\u1ED9 nh\u1EADp",
  "backup.importModeMerge": "G\u1ED9p v\u1EDBi c\xE1c m\u1EE5c hi\u1EC7n c\xF3",
  "backup.importModeReplace": "Thay th\u1EBF kho hi\u1EC7n t\u1EA1i",
  "backup.passphraseLabel": "Passphrase c\u1EE7a b\u1EA3n sao l\u01B0u",
  "backup.passphrasePlaceholder": "B\u1EAFt bu\u1ED9c v\u1EDBi b\u1EA3n sao l\u01B0u m\xE3 h\xF3a",
  "backup.importButton": "Nh\u1EADp b\u1EA3n sao l\u01B0u",
  "backup.importDone": "\u0110\xE3 nh\u1EADp b\u1EA3n sao l\u01B0u",
  "backup.importCancelled": "\u0110\xE3 h\u1EE7y nh\u1EADp b\u1EA3n sao l\u01B0u",
  "backup.reviewVerified": "\u0110\xE3 x\xE1c minh checksum b\u1EA3n sao l\u01B0u. Ch\u1ECDn G\u1ED9p \u0111\u1EC3 gi\u1EEF c\xE1c m\u1EE5c hi\u1EC7n c\xF3 ho\u1EB7c Thay th\u1EBF \u0111\u1EC3 ghi \u0111\xE8 kho.",
  "backup.reviewVerifiedKeyed": "\u0110\xE3 x\xE1c minh checksum v\u1EDBi x\xE1c th\u1EF1c kh\xF3a. Ch\u1ECDn G\u1ED9p \u0111\u1EC3 gi\u1EEF c\xE1c m\u1EE5c hi\u1EC7n c\xF3 ho\u1EB7c Thay th\u1EBF \u0111\u1EC3 ghi \u0111\xE8 kho.",
  "backup.reviewLegacy": "Ph\xE1t hi\u1EC7n b\u1EA3n sao l\u01B0u c\u0169. V\u1EABn nh\u1EADp \u0111\u01B0\u1EE3c nh\u01B0ng kh\xF4ng th\u1EC3 x\xE1c minh to\xE0n v\u1EB9n.",
  "backup.reviewNoMac": "B\u1EA3n sao l\u01B0u m\xE3 h\xF3a kh\xF4ng c\xF3 x\xE1c th\u1EF1c kh\xF3a (v2 tr\u1EDF v\u1EC1 tr\u01B0\u1EDBc). V\u1EABn nh\u1EADp \u0111\u01B0\u1EE3c nh\u01B0ng kh\xF4ng th\u1EC3 x\xE1c minh ngu\u1ED3n g\u1ED1c t\u1EC7p.",
  "backup.legacyStatus": "Ph\xE1t hi\u1EC7n b\u1EA3n sao l\u01B0u c\u0169. Nh\u1EADp m\xE0 kh\xF4ng x\xE1c minh checksum.",
  "backup.passphrasePrompt": "B\u1EA3n sao l\u01B0u \u0111\u01B0\u1EE3c m\xE3 h\xF3a. Nh\u1EADp passphrase c\u1EE7a b\u1EA3n sao l\u01B0u:",
  "backup.importCancelledNoPassphrase": "\u0110\xE3 h\u1EE7y nh\u1EADp b\u1EA3n sao l\u01B0u",
  "backup.macFailed": "Ki\u1EC3m tra x\xE1c th\u1EF1c b\u1EA3n sao l\u01B0u th\u1EA5t b\u1EA1i \u2014 t\u1EC7p \u0111\xE3 b\u1ECB s\u1EEDa \u0111\u1ED5i ho\u1EB7c \u0111\xE2y kh\xF4ng ph\u1EA3i passphrase c\u1EE7a n\xF3",
  "backup.fileNotJson": "T\u1EC7p sao l\u01B0u kh\xF4ng ph\u1EA3i JSON h\u1EE3p l\u1EC7",
  "backup.integrityVerified": "To\xE0n v\u1EB9n: checksum \u0111\xE3 x\xE1c minh",
  "backup.integrityVerifiedKeyed": "To\xE0n v\u1EB9n: checksum \u0111\xE3 x\xE1c minh (c\xF3 kh\xF3a)",
  "backup.integrityLegacy": "To\xE0n v\u1EB9n: b\u1EA3n sao l\u01B0u c\u0169",
  "backup.encryptedYes": "M\xE3 h\xF3a: c\xF3",
  "backup.encryptedNo": "M\xE3 h\xF3a: kh\xF4ng",
  "backup.schemaLine": "Schema: v{version}",
  "backup.createdLine": "T\u1EA1o l\xFAc: {date}",
  "backup.incomingItems": "S\u1ED1 m\u1EE5c nh\u1EADp v\xE0o: {count}",
  "backup.vaultSize": "K\xEDch th\u01B0\u1EDBc kho hi\u1EC7n t\u1EA1i: {count}",
  "backup.invalidSkipped": "C\u1EA7n xem l\u1EA1i: \u0111\xE3 b\u1ECF qua {count} m\u1EE5c kh\xF4ng h\u1EE3p l\u1EC7 tr\u01B0\u1EDBc khi nh\u1EADp",
  "backup.mergeSummary": "G\u1ED9p: {new} m\u1EE5c m\u1EDBi, b\u1ECF qua {duplicates} m\u1EE5c tr\xF9ng",
  "edit.eyebrow": "s\u1EEDa m\u1EE5c",
  "edit.heading": "S\u1EEDa m\u1EE5c trong kho",
  "edit.headingShort": "S\u1EEDa m\u1EE5c",
  "edit.labelField": "Nh\xE3n",
  "edit.secretField": "Secret",
  "edit.tagsField": "Nh\xE3n",
  "edit.counterField": "B\u1ED9 \u0111\u1EBFm HOTP",
  "edit.algorithmField": "Thu\u1EADt to\xE1n",
  "edit.digitsField": "S\u1ED1 ch\u1EEF s\u1ED1",
  "edit.periodField": "Chu k\u1EF3",
  "edit.save": "L\u01B0u thay \u0111\u1ED5i",
  "edit.saveShort": "L\u01B0u",
  "edit.noLongerExists": "M\u1EE5c kh\xF4ng c\xF2n t\u1ED3n t\u1EA1i",
  "edit.duplicate": "M\u1EE5c kh\xE1c \u0111\xE3 d\xF9ng secret, s\u1ED1 ch\u1EEF s\u1ED1 v\xE0 chu k\u1EF3 n\xE0y",
  "edit.digitsOption": "{digits} ch\u1EEF s\u1ED1",
  "edit.digits6": "6 ch\u1EEF s\u1ED1",
  "edit.digits8": "8 ch\u1EEF s\u1ED1",
  "confirm.eyebrow": "x\xE1c nh\u1EADn h\xE0nh \u0111\u1ED9ng nguy hi\u1EC3m",
  "confirm.defaultTitle": "B\u1EA1n c\xF3 ch\u1EAFc kh\xF4ng?",
  "confirm.defaultMessage": "H\xE0nh \u0111\u1ED9ng n\xE0y kh\xF4ng th\u1EC3 ho\xE0n t\xE1c.",
  "confirm.removeTitle": "X\xF3a m\u1EE5c n\xE0y?",
  "confirm.removeText": 'Thao t\xE1c n\xE0y s\u1EBD x\xF3a "{label}" kh\u1ECFi kho c\u1EE7a b\u1EA1n. B\u1EA1n c\xF3 th\u1EC3 ho\xE0n t\xE1c trong 10 gi\xE2y.',
  "confirm.clearAllTitle": "X\xF3a t\u1EA5t c\u1EA3 c\xE1c m\u1EE5c?",
  "confirm.clearAllText": "Thao t\xE1c n\xE0y s\u1EBD x\xF3a v\u0129nh vi\u1EC5n t\u1EA5t c\u1EA3 {count} m\u1EE5c trong kho. Kh\xF4ng th\u1EC3 ho\xE0n t\xE1c.",
  "confirm.bulkRemoveTitle": "X\xF3a c\xE1c m\u1EE5c \u0111\xE3 ch\u1ECDn?",
  "confirm.bulkRemoveText": "Thao t\xE1c n\xE0y s\u1EBD x\xF3a {count} m\u1EE5c \u0111\xE3 ch\u1ECDn kh\u1ECFi kho. B\u1EA1n c\xF3 th\u1EC3 ho\xE0n t\xE1c trong 10 gi\xE2y.",
  "confirm.replaceVaultTitle": "Thay th\u1EBF to\xE0n b\u1ED9 kho?",
  "confirm.replaceVaultText": "Thao t\xE1c n\xE0y s\u1EBD x\xF3a t\u1EA5t c\u1EA3 {count} m\u1EE5c hi\u1EC7n c\xF3 v\xE0 thay b\u1EB1ng n\u1ED9i dung b\u1EA3n sao l\u01B0u. Kh\xF4ng th\u1EC3 ho\xE0n t\xE1c.",
  "qr.eyebrow": "xu\u1EA5t m\u1EE5c",
  "qr.heading": "M\xE3 QR c\u1EE7a m\u1EE5c",
  "qr.hint": "Qu\xE9t b\u1EB1ng \u1EE9ng d\u1EE5ng authenticator kh\xE1c \u0111\u1EC3 chuy\u1EC3n m\u1EE5c n\xE0y. B\u1EA5t k\u1EF3 ai qu\xE9t \u0111\u01B0\u1EE3c m\xE3 \u0111\u1EC1u c\xF3 th\u1EC3 th\xEAm secret c\u1EE7a b\u1EA1n \u2014 h\xE3y gi\u1EEF k\xEDn.",
  "qr.canvasLabel": "M\xE3 QR OTPauth",
  "qr.copyUri": "Sao ch\xE9p URI",
  "qr.downloadPng": "T\u1EA3i PNG",
  "qr.renderFailed": "Kh\xF4ng th\u1EC3 t\u1EA1o m\xE3 QR",
  "qr.copiedUri": "\u0110\xE3 sao ch\xE9p URI otpauth",
  "ext.eyebrow": "ti\u1EC7n \xEDch",
  "ext.brand": "Kho OTP",
  "ext.subtitle": "L\u1EA5y m\xE3 nhanh t\u1EEB thanh c\xF4ng c\u1EE5.",
  "ext.addEntryHeading": "Th\xEAm m\u1EE5c",
  "ext.show": "Hi\u1EC7n",
  "ext.hide": "\u1EA8n",
  "ext.labelPlaceholder": "GitHub:user@example.com",
  "ext.secretPlaceholder": "Secret Base32",
  "ext.tagsPlaceholder": "Nh\xE3n: work, infra",
  "ext.totpOption": "TOTP (theo th\u1EDDi gian)",
  "ext.hotpOption": "HOTP (b\u1ED9 \u0111\u1EBFm)",
  "ext.qrFile": "T\u1EC7p QR",
  "ext.pasteUri": "D\xE1n URI",
  "ext.pasteGa": "D\xE1n b\u1EA3n xu\u1EA5t GA",
  "ext.addEntry": "Th\xEAm m\u1EE5c",
  "ext.lock": "Kh\xF3a",
  "ext.searchPlaceholder": "T\xECm nh\xE0 cung c\u1EA5p ho\u1EB7c t\xE0i kho\u1EA3n",
  "ext.sortAz": "A-Z",
  "ext.sortManual": "Th\u1EE7 c\xF4ng",
  "ext.sortNewest": "M\u1EDBi nh\u1EA5t",
  "ext.sortFastest": "H\u1EB9n gi\u1EDD nhanh nh\u1EA5t",
  "ext.locked": "Kho \u0111ang kh\xF3a. M\u1EDF kh\xF3a \u0111\u1EC3 xem v\xE0 d\xF9ng m\xE3 c\u1EE7a b\u1EA1n.",
  "ext.noEntries": "Ch\u01B0a c\xF3 m\u1EE5c n\xE0o. Th\xEAm m\u1EDBi, nh\u1EADp t\u1EC7p QR, ho\u1EB7c d\xE1n URI otpauth.",
  "ext.historyHeading": "L\u1ECBch s\u1EED sao ch\xE9p",
  "ext.historyEmpty": "M\xE3 OTP \u0111\xE3 sao ch\xE9p s\u1EBD hi\u1EC7n \u1EDF \u0111\xE2y.",
  "ext.copiedIssuer": "\u0110\xE3 sao ch\xE9p m\xE3 {issuer}",
  "ext.importedQr": "\u0110\xE3 nh\u1EADp m\u1EE5c t\u1EEB QR",
  "ext.importedUri": "\u0110\xE3 nh\u1EADp URI t\u1EEB clipboard",
  "ext.clipboardDenied": "T\u1EEB ch\u1ED1i quy\u1EC1n clipboard. H\xE3y d\xE1n URI v\xE0o \xF4 secret.",
  "ext.clipboardDeniedGa": "T\u1EEB ch\u1ED1i quy\u1EC1n clipboard. H\xE3y d\xE1n URI b\u1EA3n xu\u1EA5t r\u1ED3i th\u1EED l\u1EA1i.",
  "ext.noClipboardUri": "Clipboard kh\xF4ng ch\u1EE9a OTP URI h\u1EE3p l\u1EC7",
  "ext.noClipboardGa": "Clipboard kh\xF4ng ch\u1EE9a b\u1EA3n xu\u1EA5t Google Authenticator",
  "ext.imported": "\u0110\xE3 nh\u1EADp c\xE1c m\u1EE5c Google Authenticator",
  "ext.removedEntry": "\u0110\xE3 x\xF3a m\u1EE5c",
  "ext.removeConfirm": 'X\xF3a "{label}" kh\u1ECFi kho c\u1EE7a ti\u1EC7n \xEDch? B\u1EA1n c\xF3 th\u1EC3 ho\xE0n t\xE1c trong 10 ph\xFAt b\u1EB1ng c\xE1ch m\u1EDF l\u1EA1i popup.',
  "ext.removeHeading": "X\xF3a m\u1EE5c",
  "ext.cannotBeUndone": "H\xE0nh \u0111\u1ED9ng n\xE0y kh\xF4ng th\u1EC3 ho\xE0n t\xE1c.",
  "ext.undoOfferOne": "M\u1ED9t m\u1EE5c \u0111\xE3 b\u1ECB x\xF3a tr\u01B0\u1EDBc khi popup \u0111\xF3ng. Ho\xE0n t\xE1c?",
  "ext.undoOfferMany": "{count} m\u1EE5c \u0111\xE3 b\u1ECB x\xF3a tr\u01B0\u1EDBc khi popup \u0111\xF3ng. Ho\xE0n t\xE1c?",
  "ext.undoDelete": "Ho\xE0n t\xE1c x\xF3a",
  "ext.undoRemovedOne": "\u0110\xE3 x\xF3a m\u1EE5c",
  "ext.undoRemovedMany": "\u0110\xE3 x\xF3a {count} m\u1EE5c \u2014 m\u1EDF l\u1EA1i popup \u0111\u1EC3 ho\xE0n t\xE1c trong 10 ph\xFAt",
  "ext.undoNothing": "Kh\xF4ng c\xF3 g\xEC \u0111\u1EC3 ho\xE0n t\xE1c \u2014 c\xE1c m\u1EE5c \u0111\xF3 \u0111\xE3 t\u1ED3n t\u1EA1i l\u1EA1i",
  "ext.importHeading": "Nh\u1EADp m\u1EE5c",
  "ext.importApps": "Aegis / 2FAS",
  "ext.importAppsStatus": "{source}: t\xECm th\u1EA5y {count} m\u1EE5c.",
  "ext.importAppsSkipped": " {count} m\u1EE5c tr\xF9ng \u0111\u01B0\u1EE3c b\u1ECF ch\u1ECDn s\u1EB5n.",
  "ext.importAppsInvalid": " {count} m\u1EE5c kh\xF4ng \xE1nh x\u1EA1 \u0111\u01B0\u1EE3c.",
  "ext.alreadyInVaultSuffix": " (\u0111\xE3 c\xF3 trong kho)",
  "ext.biometricUnlockFailed": "M\u1EDF kh\xF3a sinh tr\u1EAFc h\u1ECDc th\u1EA5t b\u1EA1i \u2014 d\xF9ng passphrase",
  "ext.noBiometricEnrolled": "Ch\u01B0a k\xEDch ho\u1EA1t m\u1EDF kh\xF3a sinh tr\u1EAFc h\u1ECDc tr\xEAn thi\u1EBFt b\u1ECB n\xE0y",
  "ext.biometricUnavailable": "M\u1EDF kh\xF3a sinh tr\u1EAFc h\u1ECDc kh\xF4ng c\xF2n kh\u1EA3 d\u1EE5ng \u2014 d\xF9ng passphrase",
  "ext.unlocked": "\u0110\xE3 m\u1EDF kh\xF3a ti\u1EC7n \xEDch m\xE3 h\xF3a",
  "ext.encryptionRequiresUnlock": "M\u1EDF kh\xF3a kho ti\u1EC7n \xEDch tr\u01B0\u1EDBc khi l\u01B0u c\xE1c m\u1EE5c m\xE3 h\xF3a",
  "ext.lockNeedsEncryption": "H\xE3y b\u1EADt l\u01B0u tr\u1EEF m\xE3 h\xF3a tr\u01B0\u1EDBc",
  "ext.enrollNeedsEncryption": "H\xE3y b\u1EADt l\u01B0u tr\u1EEF m\xE3 h\xF3a tr\u01B0\u1EDBc khi b\u1EADt m\u1EDF kh\xF3a sinh tr\u1EAFc h\u1ECDc",
  "ext.enrollNeedsUnlock": "M\u1EDF kh\xF3a kho ti\u1EC7n \xEDch tr\u01B0\u1EDBc khi b\u1EADt m\u1EDF kh\xF3a sinh tr\u1EAFc h\u1ECDc",
  "ext.changePassphraseNeedsEncryption": "H\xE3y b\u1EADt l\u01B0u tr\u1EEF m\xE3 h\xF3a tr\u01B0\u1EDBc khi \u0111\u1ED5i passphrase c\u1EE7a ti\u1EC7n \xEDch",
  "ext.exportNeedsUnlock": "M\u1EDF kh\xF3a kho ti\u1EC7n \xEDch tr\u01B0\u1EDBc khi xu\u1EA5t b\u1EA3n sao l\u01B0u m\xE3 h\xF3a",
  "ext.passphrasePromptAction": "Nh\u1EADp passphrase c\u1EE7a kho \u0111\u1EC3 {action}:",
  "ext.actionExportBackup": "xu\u1EA5t b\u1EA3n sao l\u01B0u",
  "ext.actionDisableBiometric": "t\u1EAFt m\u1EDF kh\xF3a sinh tr\u1EAFc h\u1ECDc",
  "ext.actionChangePassphrase": "\u0111\u1ED5i passphrase c\u1EE7a ti\u1EC7n \xEDch",
  "ext.counterSaveFailed": "L\u01B0u b\u1ED9 \u0111\u1EBFm th\u1EA5t b\u1EA1i \u2014 m\xE3 ti\u1EBFp theo c\xF3 th\u1EC3 l\u1EB7p. H\xE3y s\u1EEDa m\u1EE5c \u0111\u1EC3 \u0111\u1EB7t b\u1ED9 \u0111\u1EBFm th\u1EE7 c\xF4ng.",
  "ext.tooManyAttempts": "Qu\xE1 nhi\u1EC1u l\u1EA7n th\u1EED sai \u2014 c\xF3 th\u1EC3 m\u1EDF kh\xF3a sau {seconds}s",
  "ext.lockedForSuffix": " Kh\xF3a trong {seconds}s.",
  "ext.incorrectPassphrase": "Passphrase sai ho\u1EB7c d\u1EEF li\u1EC7u m\xE3 h\xF3a kh\xF4ng \u0111\u1ECDc \u0111\u01B0\u1EE3c",
  "ext.qrNeedsBarcodeDetector": "Nh\u1EADp t\u1EC7p QR c\u1EA7n t\xEDnh n\u0103ng BarcodeDetector c\u1EE7a Chrome",
  "ext.qrNotDetected": "Kh\xF4ng ph\xE1t hi\u1EC7n m\xE3 QR trong t\u1EC7p \u0111\xF3",
  "ext.qrNoOtpUri": "Ph\xE1t hi\u1EC7n m\xE3 QR nh\u01B0ng kh\xF4ng ch\u1EE9a OTP URI h\u1EE3p l\u1EC7",
  "ext.accountExists": "T\xE0i kho\u1EA3n n\xE0y \u0111\xE3 t\u1ED3n t\u1EA1i",
  "ext.hotpCounterBadge": "#{counter}",
  "ext.secondsBadge": "{seconds}s",
  "ext.globalTimerLabel": "H\u1EB9n gi\u1EDD l\xE0m m\u1EDBi OTP",
  "vault.passphrasePrompt": "Nh\u1EADp passphrase c\u1EE7a kho \u0111\u1EC3 {action}:",
  "vault.passphraseRequired": "C\u1EA7n passphrase c\u1EE7a kho cho h\xE0nh \u0111\u1ED9ng n\xE0y",
  "vault.actionExportBackup": "xu\u1EA5t b\u1EA3n sao l\u01B0u",
  "vault.actionImportBackup": "nh\u1EADp b\u1EA3n sao l\u01B0u",
  "vault.actionDisableBiometric": "t\u1EAFt m\u1EDF kh\xF3a sinh tr\u1EAFc h\u1ECDc",
  "vault.actionChangePassphrase": "\u0111\u1ED5i passphrase c\u1EE7a kho",
  "vault.staleTab": "Kho m\xE3 \u0111\xE3 thay \u0111\u1ED5i \u1EDF tab kh\xE1c \u2014 h\xE3y t\u1EA3i l\u1EA1i tab n\xE0y \u0111\u1EC3 c\xF3 th\u1EC3 thay \u0111\u1ED5i",
  "vault.needsUnlockToSave": "M\u1EDF kh\xF3a ho\u1EB7c \u0111\u1EB7t passphrase tr\u01B0\u1EDBc khi l\u01B0u c\xE1c m\u1EE5c m\xE3 h\xF3a",
  "vault.needsPassphraseToEncrypt": "Nh\u1EADp passphrase \u0111\u1EC3 b\u1EADt m\xE3 h\xF3a",
  "vault.confirmationMismatch": "X\xE1c nh\u1EADn passphrase kh\xF4ng kh\u1EDBp",
  "vault.currentIncorrect": "Passphrase hi\u1EC7n t\u1EA1i kh\xF4ng \u0111\xFAng",
  "vault.changeNeedsEncryption": "H\xE3y b\u1EADt l\u01B0u tr\u1EEF m\xE3 h\xF3a tr\xEAn thi\u1EBFt b\u1ECB tr\u01B0\u1EDBc khi \u0111\u1ED5i passphrase c\u1EE7a kho",
  "vault.hotpSaveFailed": "L\u01B0u b\u1ED9 \u0111\u1EBFm th\u1EA5t b\u1EA1i \u2014 m\xE3 ti\u1EBFp theo c\xF3 th\u1EC3 l\u1EB7p. D\xF9ng S\u1EEDa tr\xEAn m\u1EE5c n\xE0y \u0111\u1EC3 \u0111\u1EB7t b\u1ED9 \u0111\u1EBFm th\u1EE7 c\xF4ng.",
  "vault.accountExists": "T\xE0i kho\u1EA3n n\xE0y \u0111\xE3 t\u1ED3n t\u1EA1i",
  "vault.tooManyAttempts": "Qu\xE1 nhi\u1EC1u l\u1EA7n th\u1EED sai \u2014 c\xF3 th\u1EC3 m\u1EDF kh\xF3a sau {seconds}s",
  "vault.lockedForSuffix": " Kh\xF3a trong {seconds}s.",
  "vault.noNewEntries": "Kh\xF4ng t\xECm th\u1EA5y m\u1EE5c m\u1EDBi t\u1EEB {source}{details}",
  "vault.noImportable": "Kh\xF4ng c\xF3 m\u1EE5c nh\u1EADp \u0111\u01B0\u1EE3c trong b\u1EA3n xu\u1EA5t {source}{details}",
  "vault.noEntriesToClear": "Kh\xF4ng c\xF3 m\u1EE5c n\xE0o \u0111\u1EC3 x\xF3a",
  "vault.allCleared": "\u0110\xE3 x\xF3a t\u1EA5t c\u1EA3 c\xE1c m\u1EE5c",
  "vault.tagsApplied": "\u0110\xE3 g\u1EAFn nh\xE3n cho c\xE1c m\u1EE5c \u0111\xE3 ch\u1ECDn",
  "vault.tagsRequired": "H\xE3y nh\u1EADp \xEDt nh\u1EA5t m\u1ED9t nh\xE3n cho c\xE1c m\u1EE5c \u0111\xE3 ch\u1ECDn",
  "vault.selectedRemoved": "\u0110\xE3 x\xF3a c\xE1c m\u1EE5c \u0111\xE3 ch\u1ECDn",
  "vault.bulkRemoveFailed": "Kh\xF4ng th\u1EC3 x\xF3a c\xE1c m\u1EE5c \u0111\xE3 ch\u1ECDn",
  "vault.reorderFailed": "Kh\xF4ng th\u1EC3 s\u1EAFp x\u1EBFp l\u1EA1i c\xE1c m\u1EE5c",
  "vault.reorderEntryFailed": "Kh\xF4ng th\u1EC3 s\u1EAFp x\u1EBFp l\u1EA1i m\u1EE5c",
  "vault.copyFailedShort": "Kh\xF4ng th\u1EC3 sao ch\xE9p m\xE3 OTP",
  "vault.removeFailed": "Kh\xF4ng th\u1EC3 x\xF3a m\u1EE5c",
  "vault.updateFailed": "Kh\xF4ng th\u1EC3 c\u1EADp nh\u1EADt m\u1EE5c",
  "vault.addFailed": "Kh\xF4ng th\u1EC3 th\xEAm m\u1EE5c",
  "vault.duplicatesSkipped": "\u0111\xE3 b\u1ECF qua {count} m\u1EE5c tr\xF9ng",
  "vault.invalidIgnored": "\u0111\xE3 b\u1ECF qua {count} URI kh\xF4ng h\u1EE3p l\u1EC7",
  "vault.biometricEnrollmentFailed": "Kh\xF4ng th\u1EC3 b\u1EADt m\u1EDF kh\xF3a sinh tr\u1EAFc h\u1ECDc",
  "vault.biometricDisenrollFailed": "Kh\xF4ng th\u1EC3 t\u1EAFt m\u1EDF kh\xF3a sinh tr\u1EAFc h\u1ECDc",
  "vault.pinFailed": "Kh\xF4ng th\u1EC3 c\u1EADp nh\u1EADt th\u1EE9 t\u1EF1 m\u1EE5c",
  "vault.needsUnlockToExport": "M\u1EDF kh\xF3a kho tr\u01B0\u1EDBc khi xu\u1EA5t b\u1EA3n sao l\u01B0u m\xE3 h\xF3a",
  "vault.clearFailed": "Kh\xF4ng th\u1EC3 x\xF3a c\xE1c m\u1EE5c",
  "import.gaFailed": "Kh\xF4ng th\u1EC3 nh\u1EADp b\u1EA3n xu\u1EA5t Google Authenticator",
  "import.uriImported": "{source}: \u0111\xE3 nh\u1EADp t\xE0i kho\u1EA3n",
  "import.qrNotDetectedImage": "Kh\xF4ng ph\xE1t hi\u1EC7n m\xE3 QR trong \u1EA3nh \u0111\xF3",
  "import.qrUrlDownloadFailed": "Kh\xF4ng th\u1EC3 t\u1EA3i \u1EA3nh QR t\u1EEB URL",
  "import.commitFailed": "Kh\xF4ng th\u1EC3 nh\u1EADp c\xE1c m\u1EE5c",
  "import.fileTooLarge": "T\u1EC7p nh\u1EADp v\u01B0\u1EE3t qu\xE1 gi\u1EDBi h\u1EA1n 8 MB",
  "import.mapFailed": "Kh\xF4ng th\u1EC3 \xE1nh x\u1EA1 m\u1ED9t m\u1EE5c",
  "backup.lastExportShortSuffix": ". Kh\xF4ng th\u1EC3 ph\xE1t hi\u1EC7n l\u01B0\u1EE3t t\u1EA3i b\u1ECB h\u1EE7y.",
  "ext.qrImportFailed": "Kh\xF4ng th\u1EC3 nh\u1EADp t\u1EC7p QR",
  "ext.uriImportFailed": "Kh\xF4ng th\u1EC3 nh\u1EADp URI",
  "settings.extensionSaveFailed": "Kh\xF4ng th\u1EC3 l\u01B0u c\xE0i \u0111\u1EB7t b\u1EA3o m\u1EADt",
  "settings.updateFailed": "Kh\xF4ng th\u1EC3 c\u1EADp nh\u1EADt passphrase",
  "ext.envelopeMissing": "Thi\u1EBFu phong b\xEC kho sinh tr\u1EAFc h\u1ECDc \u2014 m\u1EDF kh\xF3a b\u1EB1ng passphrase \u0111\u1EC3 kh\xF4i ph\u1EE5c",
  "strength.veryWeak": "R\u1EA5t y\u1EBFu",
  "strength.weak": "Y\u1EBFu",
  "strength.fair": "T\u1EA1m \u0111\u01B0\u1EE3c",
  "strength.good": "T\u1ED1t",
  "strength.strong": "M\u1EA1nh",
  "strength.enterPassphrase": "Nh\u1EADp passphrase",
  "strength.avoidCommon": "Tr\xE1nh c\xE1c t\u1EEB v\xE0 m\u1EABu ph\u1ED5 bi\u1EBFn",
  "strength.useTwelve": "D\xF9ng \xEDt nh\u1EA5t 12 k\xFD t\u1EF1 \u0111\u1EC3 passphrase m\u1EA1nh h\u01A1n"
};
var catalogs = /* @__PURE__ */ new Map([
  [DEFAULT_LOCALE, { ...en }],
  ["vi", { ...en, ...vi }]
]);
var activeLocale = DEFAULT_LOCALE;
function setLocale(locale) {
  const localeName = typeof locale === "string" ? locale.trim() : "";
  if (!localeName || !catalogs.has(localeName)) {
    throw new OtpVaultError(`Unknown locale: ${localeName || String(locale)}`, { code: "LOCALE_UNKNOWN" });
  }
  activeLocale = localeName;
  return activeLocale;
}
function resolveLocale(setting) {
  const candidate = typeof setting === "string" ? setting.trim() : "";
  if (candidate && catalogs.has(candidate)) return candidate;
  if (candidate && candidate !== "system") return DEFAULT_LOCALE;
  if (typeof navigator === "undefined") return DEFAULT_LOCALE;
  const languages = Array.isArray(navigator.languages) ? navigator.languages : navigator.language ? [navigator.language] : [];
  for (const language of languages) {
    const lower = String(language).toLowerCase();
    if (catalogs.has(lower)) return lower;
    const base = lower.split("-")[0];
    if (catalogs.has(base)) return base;
  }
  return DEFAULT_LOCALE;
}
function t(key, params) {
  return interpolate(resolveTemplate(key), params);
}
function resolveTemplate(key) {
  if (typeof key !== "string" || !key) return key;
  const value = catalogs.get(activeLocale)?.[key] ?? catalogs.get(DEFAULT_LOCALE)?.[key];
  return typeof value === "string" ? value : key;
}
function interpolate(template2, params) {
  if (typeof template2 !== "string") return template2;
  if (!params || typeof params !== "object") return template2;
  return template2.replace(PLACEHOLDER_PATTERN, (match, name) => Object.prototype.hasOwnProperty.call(params, name) ? String(params[name]) : match);
}
function applyTranslations(root = typeof document !== "undefined" ? document : null) {
  if (!root || typeof root.querySelectorAll !== "function") return;
  for (const node of root.querySelectorAll("[data-i18n]")) {
    const text = t(node.getAttribute("data-i18n"));
    if (typeof text === "string") node.textContent = text;
  }
  for (const node of root.querySelectorAll("[data-i18n-placeholder]")) {
    const text = t(node.getAttribute("data-i18n-placeholder"));
    if (typeof text === "string") node.setAttribute("placeholder", text);
  }
  for (const node of root.querySelectorAll("[data-i18n-aria-label]")) {
    const text = t(node.getAttribute("data-i18n-aria-label"));
    if (typeof text === "string") node.setAttribute("aria-label", text);
  }
  for (const node of root.querySelectorAll("[data-i18n-title]")) {
    const text = t(node.getAttribute("data-i18n-title"));
    if (typeof text === "string") node.setAttribute("title", text);
  }
}
var STRENGTH_LABEL_KEYS = {
  "Very weak": "strength.veryWeak",
  Weak: "strength.weak",
  Fair: "strength.fair",
  Good: "strength.good",
  Strong: "strength.strong"
};
var STRENGTH_WARNING_KEYS = {
  "Enter a passphrase": "strength.enterPassphrase",
  "Avoid common words and patterns": "strength.avoidCommon",
  "Use at least 12 characters for a stronger passphrase": "strength.useTwelve"
};
function translateStrengthAssessment(assessment) {
  return {
    ...assessment,
    label: STRENGTH_LABEL_KEYS[assessment?.label] ? t(STRENGTH_LABEL_KEYS[assessment.label]) : assessment?.label,
    warnings: (assessment?.warnings || []).map((warning) => STRENGTH_WARNING_KEYS[warning] ? t(STRENGTH_WARNING_KEYS[warning]) : warning)
  };
}

// lib/importers.js
var MAX_IMPORT_FILE_BYTES = 8 * 1024 * 1024;
var MAX_IMPORT_ENTRIES = 500;
var OTP_TYPES2 = /* @__PURE__ */ new Set(["totp", "hotp"]);
var ALGORITHMS = /* @__PURE__ */ new Set(["SHA1", "SHA256", "SHA512"]);
var MIN_PERIOD2 = 15;
var MAX_PERIOD2 = 120;
var MAX_SAFE_COUNTER2 = Number.MAX_SAFE_INTEGER;
function malformed(message, code = "IMPORT_FILE_MALFORMED") {
  return new OtpVaultError(message, { code });
}
function toCandidate({ label, secret, type, algorithm, digits, period, counter, tags = [] }) {
  const normalizedSecret = sanitizeBase32(secret);
  if (!normalizedSecret) throw malformed("entry has no secret");
  if (!/^[A-Z2-7]+$/.test(normalizedSecret)) throw malformed("entry has an invalid Base32 secret");
  if (base32ToBytes(normalizedSecret).length === 0) throw malformed("entry secret is too short to decode");
  const normalizedType = String(type || "totp").toLowerCase();
  if (!OTP_TYPES2.has(normalizedType)) throw malformed(`unsupported OTP type "${type}"`);
  const normalizedAlgorithm = String(algorithm || "SHA1").toUpperCase();
  if (!ALGORITHMS.has(normalizedAlgorithm)) throw malformed(`unsupported algorithm "${algorithm}"`);
  const normalizedDigits = Number(digits);
  if (normalizedDigits !== 6 && normalizedDigits !== 8) throw malformed(`unsupported digit count "${digits}"`);
  const normalizedPeriod = Number(period);
  if (!Number.isInteger(normalizedPeriod) || normalizedPeriod < MIN_PERIOD2 || normalizedPeriod > MAX_PERIOD2) {
    throw malformed(`period ${period} is outside ${MIN_PERIOD2}-${MAX_PERIOD2} seconds`);
  }
  let normalizedCounter = 0;
  if (normalizedType === "hotp") {
    normalizedCounter = Number(counter ?? 0);
    if (!Number.isInteger(normalizedCounter) || normalizedCounter < 0 || normalizedCounter > MAX_SAFE_COUNTER2) {
      throw malformed("HOTP counter is outside the supported range");
    }
  }
  const normalizedLabel = String(label || "").trim();
  if (!normalizedLabel) throw malformed("entry has no label");
  return {
    label: normalizedLabel,
    secret: normalizedSecret,
    type: normalizedType,
    algorithm: normalizedAlgorithm,
    digits: normalizedDigits,
    period: normalizedPeriod,
    counter: normalizedCounter,
    tags: (Array.isArray(tags) ? tags : []).map((tag) => String(tag).trim()).filter(Boolean).slice(0, 8)
  };
}
function buildLabel(issuer, name) {
  const cleanIssuer = String(issuer || "").trim();
  const cleanName = String(name || "").trim();
  if (!cleanIssuer) return cleanName;
  if (!cleanName) return cleanIssuer;
  if (cleanName.toLowerCase().startsWith(`${cleanIssuer.toLowerCase()}:`)) return cleanName;
  return `${cleanIssuer}:${cleanName}`;
}
function looksLikeEncryptedAegis(data) {
  return Array.isArray(data?.header?.slots) || Boolean(data?.header?.params);
}
function parseAegisExport(data) {
  const entriesRaw = data?.db?.entries;
  if (!Array.isArray(entriesRaw)) {
    if (looksLikeEncryptedAegis(data)) {
      throw malformed(
        "This Aegis export is encrypted. Re-export from Aegis with the plain-text (unencrypted) option and try again.",
        "IMPORT_ENCRYPTED_UNSUPPORTED"
      );
    }
    throw malformed("This file does not look like an Aegis export (no entry database found)");
  }
  const entries2 = [];
  const warnings = [];
  for (const raw of entriesRaw) {
    const label = buildLabel(raw?.issuer, raw?.name || raw?.token?.label);
    if (entries2.length >= MAX_IMPORT_ENTRIES) {
      warnings.push(`Stopped at the ${MAX_IMPORT_ENTRIES} entry limit; remaining Aegis entries were not imported`);
      break;
    }
    try {
      entries2.push(toCandidate({
        label,
        secret: raw?.token?.secret,
        type: raw?.type,
        algorithm: raw?.token?.algorithm,
        digits: raw?.token?.digits ?? 6,
        period: raw?.token?.period ?? 30,
        counter: raw?.token?.counter,
        tags: Array.isArray(raw?.tags) ? raw.tags : []
      }));
    } catch (error) {
      warnings.push(`Skipped "${label || "unnamed entry"}": ${error.message}`);
    }
  }
  return { entries: entries2, warnings };
}
function parse2FasExport(data) {
  const servicesRaw = data?.services;
  if (!Array.isArray(servicesRaw)) {
    throw malformed("This file does not look like a 2FAS export (no services found)");
  }
  const groupNames = /* @__PURE__ */ new Map();
  if (Array.isArray(data?.groups)) {
    for (const group of data.groups) {
      if (group?.uuid && group?.name) groupNames.set(group.uuid, String(group.name));
    }
  }
  const entries2 = [];
  const warnings = [];
  for (const raw of servicesRaw) {
    const otp = raw?.otp || {};
    const issuer = otp.tokenIssuer || raw?.name;
    const label = buildLabel(issuer, otp.label);
    if (entries2.length >= MAX_IMPORT_ENTRIES) {
      warnings.push(`Stopped at the ${MAX_IMPORT_ENTRIES} entry limit; remaining 2FAS entries were not imported`);
      break;
    }
    try {
      const tags = [];
      if (raw?.groupUuid && groupNames.has(raw.groupUuid)) tags.push(groupNames.get(raw.groupUuid));
      entries2.push(toCandidate({
        label,
        secret: otp.secret ?? raw?.secret,
        type: otp.tokenType,
        algorithm: otp.algorithm,
        digits: otp.digits ?? 6,
        period: otp.period ?? 30,
        counter: otp.counter,
        tags
      }));
    } catch (error) {
      warnings.push(`Skipped "${label || "unnamed entry"}": ${error.message}`);
    }
  }
  return { entries: entries2, warnings };
}
function parseThirdPartyImport(rawText) {
  const text = typeof rawText === "string" ? rawText : "";
  if (text.length > MAX_IMPORT_FILE_BYTES) {
    throw malformed(`Import file exceeds the ${MAX_IMPORT_FILE_BYTES} byte limit`);
  }
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    throw malformed("Import file is not valid JSON");
  }
  if (!data || typeof data !== "object" || Array.isArray(data)) {
    throw malformed("Import file is not a recognized export format");
  }
  if (Array.isArray(data.services)) {
    const { entries: entries2, warnings } = parse2FasExport(data);
    return { format: "2FAS", entries: entries2, warnings };
  }
  if (Array.isArray(data.db?.entries) || looksLikeEncryptedAegis(data)) {
    const { entries: entries2, warnings } = parseAegisExport(data);
    return { format: "Aegis", entries: entries2, warnings };
  }
  throw malformed("Import file is not a recognized Aegis or 2FAS export");
}

// lib/migration.js
var MAX_BATCH_SIZE = 10;
var MAX_STITCHED_ENTRIES = 500;
var MAX_PAYLOAD_BYTES = 64 * 1024;
var MAX_SAFE_COUNTER3 = BigInt(Number.MAX_SAFE_INTEGER);
var ALGORITHM_NAMES = { 0: "SHA1", 1: "SHA1", 2: "SHA256", 3: "SHA512" };
var BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
var BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
var BASE64_LOOKUP = new Int8Array(256).fill(-1);
for (let index = 0; index < BASE64_ALPHABET.length; index += 1) {
  BASE64_LOOKUP[BASE64_ALPHABET.charCodeAt(index)] = index;
}
var TEXT_DECODER = new TextDecoder("utf-8");
function malformed2(message) {
  return new OtpVaultError(message, { code: "MIGRATION_DATA_MALFORMED" });
}
function toInt32(value) {
  return Number(BigInt.asIntN(32, value));
}
function varint(bytes, pos) {
  let value = 0n;
  let shift = 0n;
  for (; ; ) {
    if (pos >= bytes.length) {
      throw malformed2("Migration payload ends inside a varint");
    }
    const byte = bytes[pos];
    pos += 1;
    value |= BigInt(byte & 127) << shift;
    if ((byte & 128) === 0) return [value, pos];
    shift += 7n;
    if (shift >= 70n) {
      throw malformed2("Migration payload contains an overlong varint");
    }
  }
}
function skipField(bytes, pos, wireType) {
  if (wireType === 0) return varint(bytes, pos)[1];
  if (wireType === 1) {
    if (pos + 8 > bytes.length) throw malformed2("Migration payload has a truncated fixed64 field");
    return pos + 8;
  }
  if (wireType === 2) return lenBytes(bytes, pos)[1];
  if (wireType === 5) {
    if (pos + 4 > bytes.length) throw malformed2("Migration payload has a truncated fixed32 field");
    return pos + 4;
  }
  throw malformed2(`Migration payload uses unsupported wire type ${wireType}`);
}
function lenBytes(bytes, pos) {
  const [length, start] = varint(bytes, pos);
  const end = start + Number(length);
  if (end > bytes.length) {
    throw malformed2("Migration payload has a truncated length-delimited field");
  }
  return [bytes.subarray(start, end), end];
}
function decodeOtpParameters(bytes) {
  const params = { secret: new Uint8Array(0), name: "", issuer: "", algorithm: 0, digits: 0, type: 0, counter: 0n };
  let pos = 0;
  while (pos < bytes.length) {
    const [key, next] = varint(bytes, pos);
    pos = next;
    const field = Number(key >> 3n);
    const wireType = Number(key & 7n);
    if (field === 1 && wireType === 2) {
      [params.secret, pos] = lenBytes(bytes, pos);
    } else if ((field === 2 || field === 3) && wireType === 2) {
      const [value, after] = lenBytes(bytes, pos);
      pos = after;
      const text = TEXT_DECODER.decode(value);
      if (field === 2) params.name = text;
      else params.issuer = text;
    } else if (field >= 4 && field <= 6 && wireType === 0) {
      const [value, after] = varint(bytes, pos);
      pos = after;
      if (field === 4) params.algorithm = Number(value);
      else if (field === 5) params.digits = Number(value);
      else params.type = Number(value);
    } else if (field === 7 && wireType === 0) {
      const [value, after] = varint(bytes, pos);
      pos = after;
      params.counter = BigInt.asIntN(64, value);
    } else {
      pos = skipField(bytes, pos, wireType);
    }
  }
  return params;
}
function scanPayload(bytes) {
  const entryRanges = [];
  let version;
  let batchSize;
  let batchIndex;
  let batchId;
  let pos = 0;
  while (pos < bytes.length) {
    const [key, next] = varint(bytes, pos);
    pos = next;
    const field = Number(key >> 3n);
    const wireType = Number(key & 7n);
    if (field === 1 && wireType === 2) {
      const [length, start] = varint(bytes, pos);
      const end = start + Number(length);
      if (end > bytes.length) throw malformed2("Migration payload has a truncated entry");
      entryRanges.push([start, end]);
      pos = end;
    } else if (field >= 2 && field <= 5 && wireType === 0) {
      const [value, after] = varint(bytes, pos);
      pos = after;
      if (field === 2) version = value;
      else if (field === 3) batchSize = value;
      else if (field === 4) batchIndex = value;
      else batchId = value;
    } else {
      pos = skipField(bytes, pos, wireType);
    }
  }
  return { entryRanges, version, batchSize, batchIndex, batchId };
}
function decodeMigrationPayload(bytes) {
  if (!(bytes instanceof Uint8Array)) {
    throw malformed2("Migration payload must be raw bytes");
  }
  if (bytes.length > MAX_PAYLOAD_BYTES) {
    throw malformed2(`Migration payload exceeds the ${MAX_PAYLOAD_BYTES} byte limit`);
  }
  const scanned = scanPayload(bytes);
  const batchSize = scanned.batchSize === void 0 ? 1 : toInt32(scanned.batchSize);
  const batchIndex = scanned.batchIndex === void 0 ? 0 : toInt32(scanned.batchIndex);
  if (batchSize < 1 || batchSize > MAX_BATCH_SIZE) {
    throw malformed2(`Migration batch size ${batchSize} is outside the allowed range 1-${MAX_BATCH_SIZE}`);
  }
  if (batchIndex < 0 || batchIndex >= batchSize) {
    throw malformed2(`Migration batch index ${batchIndex} is outside the batch size ${batchSize}`);
  }
  const entries2 = scanned.entryRanges.map(([start, end]) => decodeOtpParameters(bytes.subarray(start, end)));
  return {
    entries: entries2,
    version: scanned.version === void 0 ? 0 : toInt32(scanned.version),
    batchSize,
    batchIndex,
    batchId: scanned.batchId === void 0 ? 0 : toInt32(scanned.batchId)
  };
}
function b64DecodeBytes(value) {
  if (typeof value !== "string") {
    throw malformed2("Migration data must be a base64 string");
  }
  const normalized = value.replace(/\s+/g, "").replace(/-/g, "+").replace(/_/g, "/").replace(/=+$/, "");
  if (normalized.length % 4 === 1) {
    throw malformed2("Migration data is not valid base64");
  }
  if (normalized.length > Math.ceil(MAX_PAYLOAD_BYTES / 3) * 4) {
    throw malformed2(`Migration data exceeds the ${MAX_PAYLOAD_BYTES} byte payload limit`);
  }
  const out = new Uint8Array(Math.ceil(normalized.length * 3 / 4));
  let outLength = 0;
  let acc = 0;
  let bits = 0;
  for (let index = 0; index < normalized.length; index += 1) {
    const code = normalized.charCodeAt(index);
    const decoded = code < 256 ? BASE64_LOOKUP[code] : -1;
    if (decoded === -1) {
      throw malformed2("Migration data is not valid base64");
    }
    acc = acc << 6 | decoded;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[outLength] = acc >>> bits & 255;
      outLength += 1;
    }
  }
  return out.subarray(0, outLength);
}
function parseMigrationUri(uri) {
  const raw = typeof uri === "string" ? uri.trim() : "";
  if (!raw.toLowerCase().startsWith("otpauth-migration://")) {
    throw new OtpVaultError("URI must be an otpauth-migration:// export URI", { code: "MIGRATION_URI_INVALID" });
  }
  const queryIndex = raw.indexOf("?");
  if (queryIndex === -1) {
    throw new OtpVaultError("Migration URI is missing the data parameter", { code: "MIGRATION_URI_INVALID" });
  }
  let dataParam;
  for (const pair of raw.slice(queryIndex + 1).split("&")) {
    const equals = pair.indexOf("=");
    const key = equals === -1 ? pair : pair.slice(0, equals);
    if (key.toLowerCase() === "data") {
      dataParam = equals === -1 ? "" : pair.slice(equals + 1);
      break;
    }
  }
  if (!dataParam) {
    throw new OtpVaultError("Migration URI is missing the data parameter", { code: "MIGRATION_URI_INVALID" });
  }
  let data = dataParam;
  try {
    data = decodeURIComponent(dataParam);
  } catch {
  }
  data = data.replace(/ /g, "+");
  const payloadBytes = b64DecodeBytes(data);
  const payload = decodeMigrationPayload(payloadBytes);
  const { entries: entries2, warnings } = filterMigrationEntries(payload.entries);
  return {
    entries: entries2,
    warnings,
    batch: { size: payload.batchSize, index: payload.batchIndex, id: payload.batchId },
    // Raw decoded payload bytes so multi-QR camera flows can accumulate and
    // stitch via stitchMigrationBatches without re-parsing the URI.
    payloadBytes
  };
}
function entryDisplayName(params) {
  const name = (params.name || "").trim();
  if (name) return name;
  const issuer = (params.issuer || "").trim();
  return issuer || "unnamed entry";
}
function filterMigrationEntries(rawEntries) {
  const entries2 = [];
  const warnings = [];
  for (const params of rawEntries) {
    const label = entryDisplayName(params);
    if (!params.secret.length) {
      warnings.push(`Skipped "${label}": entry has no secret`);
      continue;
    }
    if (params.algorithm === 4) {
      warnings.push(`Skipped "${label}": unsupported algorithm (MD5)`);
      continue;
    }
    if (params.algorithm > 3) {
      warnings.push(`Skipped "${label}": unsupported algorithm (code ${params.algorithm})`);
      continue;
    }
    if (params.digits > 2) {
      warnings.push(`Skipped "${label}": unsupported digits code ${params.digits}`);
      continue;
    }
    if (params.type > 2) {
      warnings.push(`Skipped "${label}": unsupported OTP type code ${params.type}`);
      continue;
    }
    if (params.counter < 0n) {
      warnings.push(`Skipped "${label}": invalid negative HOTP counter`);
      continue;
    }
    if (params.counter > MAX_SAFE_COUNTER3) {
      warnings.push(`Skipped "${label}": HOTP counter exceeds the supported range`);
      continue;
    }
    entries2.push(params);
  }
  return { entries: entries2, warnings };
}
function bytesToHex(bytes) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}
function bytesToBase32(bytes) {
  let output = "";
  let acc = 0;
  let bits = 0;
  for (const byte of bytes) {
    acc = acc << 8 | byte;
    bits += 8;
    while (bits >= 5) {
      output += BASE32_ALPHABET[acc >>> bits - 5 & 31];
      bits -= 5;
    }
  }
  if (bits > 0) output += BASE32_ALPHABET[acc << 5 - bits & 31];
  return output;
}
function buildMigrationLabel(params) {
  const issuer = (params.issuer || "").trim();
  const name = (params.name || "").trim();
  if (!issuer) {
    const colon = name.indexOf(":");
    if (colon === -1) return name;
    const nameIssuer = name.slice(0, colon).trim();
    const account = name.slice(colon + 1).trim();
    if (!account) return nameIssuer;
    if (!nameIssuer) return account;
    return `${nameIssuer}:${account}`;
  }
  if (!name) return issuer;
  if (name.toLowerCase().startsWith(`${issuer.toLowerCase()}:`)) return name;
  return `${issuer}:${name}`;
}
function migrationToEntryCandidates(entries2) {
  const source = Array.isArray(entries2) ? entries2 : [];
  return source.map((params) => {
    const algorithm = ALGORITHM_NAMES[params.algorithm];
    if (!algorithm) {
      throw malformed2(`Unsupported migration algorithm code ${params.algorithm}`);
    }
    if (params.digits !== 0 && params.digits !== 1 && params.digits !== 2) {
      throw malformed2(`Unsupported migration digits code ${params.digits}`);
    }
    if (params.type !== 0 && params.type !== 1 && params.type !== 2) {
      throw malformed2(`Unsupported migration OTP type code ${params.type}`);
    }
    const counter = BigInt(params.counter ?? 0n);
    if (counter < 0n || counter > MAX_SAFE_COUNTER3) {
      throw malformed2("Migration HOTP counter is outside the supported range");
    }
    return {
      label: buildMigrationLabel(params),
      secret: bytesToBase32(params.secret),
      digits: params.digits === 2 ? 8 : 6,
      // QR enum: 0 unspecified, 1 = SIX, 2 = EIGHT
      period: 30,
      // the payload has no period field; GA assumes 30s
      // CRITICAL: the migration QR enum order (1 = HOTP, 2 = TOTP) is the
      // OPPOSITE of Google Authenticator's internal SQLite DB order
      // (TOTP = 0, HOTP = 1 — see Aegis GoogleAuthImporter). Never share one
      // mapping between the two formats.
      type: params.type === 1 ? "hotp" : "totp",
      counter: Number(counter),
      algorithm
    };
  });
}
function stitchMigrationBatches(payloads) {
  if (!Array.isArray(payloads)) {
    throw malformed2("Migration payloads must be an array of byte arrays");
  }
  const warnings = [];
  const groups = /* @__PURE__ */ new Map();
  for (const bytes of payloads) {
    const payload = decodeMigrationPayload(bytes);
    const { entries: entries3, warnings: entryWarnings } = filterMigrationEntries(payload.entries);
    warnings.push(...entryWarnings);
    let group = groups.get(payload.batchId);
    if (!group) {
      group = { id: payload.batchId, size: payload.batchSize, scanned: /* @__PURE__ */ new Set(), buckets: /* @__PURE__ */ new Map() };
      groups.set(payload.batchId, group);
    }
    if (group.size !== payload.batchSize) {
      throw malformed2("Migration payloads disagree on the batch size");
    }
    group.scanned.add(payload.batchIndex);
    if (!group.buckets.has(payload.batchIndex)) {
      group.buckets.set(payload.batchIndex, []);
    }
    group.buckets.get(payload.batchIndex).push(...entries3);
  }
  const entries2 = [];
  const batches = [];
  const seen = /* @__PURE__ */ new Set();
  let capped = false;
  outer: for (const group of groups.values()) {
    batches.push({
      id: group.id,
      size: group.size,
      scannedIndexes: [...group.scanned].sort((a, b) => a - b)
    });
    for (let index = 0; index < group.size; index += 1) {
      for (const params of group.buckets.get(index) || []) {
        if (entries2.length >= MAX_STITCHED_ENTRIES) {
          capped = true;
          break outer;
        }
        const key = `${bytesToHex(params.secret)}|${params.name}`;
        if (seen.has(key)) continue;
        seen.add(key);
        entries2.push(params);
      }
    }
  }
  if (capped) {
    warnings.push(`Stopped at the ${MAX_STITCHED_ENTRIES} entry limit; remaining entries were not imported`);
  }
  return { entries: entries2, warnings, batches };
}

// lib/vault.js
var encoder = new TextEncoder();
var decoder = new TextDecoder();
var BACKUP_VERSION = 3;
var BACKUP_MAC_INFO = "otp-vault-backup-mac-v1";
var KDF_PARAMS_DEFAULT = Object.freeze({
  algorithm: "PBKDF2",
  iterations: 6e5,
  hash: "SHA-256",
  saltBytes: 16
});
var KDF_PARAMS_LEGACY = Object.freeze({
  algorithm: "PBKDF2",
  iterations: 15e4,
  hash: "SHA-256",
  saltBytes: 16
});
var KDF_ITERATIONS_CEILING = 5e6;
function toBase64(uint8) {
  if (typeof Buffer !== "undefined") {
    return Buffer.from(uint8).toString("base64");
  }
  return btoa(String.fromCharCode(...uint8));
}
function fromBase64(base64) {
  try {
    if (typeof Buffer !== "undefined") {
      return new Uint8Array(Buffer.from(base64, "base64"));
    }
    return Uint8Array.from(atob(base64), (char) => char.charCodeAt(0));
  } catch (error) {
    throw new OtpVaultError("Encrypted data is unreadable", { code: "VAULT_BASE64", cause: error });
  }
}
function requireCrypto(cryptoApi = globalThis.crypto) {
  if (!cryptoApi?.subtle || typeof cryptoApi.getRandomValues !== "function") {
    throw new OtpVaultError("Browser crypto support is unavailable", { code: "CRYPTO_UNAVAILABLE" });
  }
  return cryptoApi;
}
function toHex(buffer) {
  return [...new Uint8Array(buffer)].map((part) => part.toString(16).padStart(2, "0")).join("");
}
async function sha256Hex(value, cryptoApi = globalThis.crypto) {
  const safeCrypto = requireCrypto(cryptoApi);
  const digest = await safeCrypto.subtle.digest("SHA-256", encoder.encode(value));
  return toHex(digest);
}
async function deriveBackupMacKey(passphrase, saltBytes, params, cryptoApi) {
  const safeCrypto = requireCrypto(cryptoApi);
  const infoBytes = encoder.encode(BACKUP_MAC_INFO);
  const prefixedSalt = new Uint8Array(infoBytes.length + saltBytes.length);
  prefixedSalt.set(infoBytes, 0);
  prefixedSalt.set(saltBytes, infoBytes.length);
  const material = await safeCrypto.subtle.importKey("raw", encoder.encode(passphrase), "PBKDF2", false, ["deriveKey"]);
  return safeCrypto.subtle.deriveKey(
    { name: "PBKDF2", salt: prefixedSalt, iterations: params.iterations, hash: params.hash },
    material,
    { name: "HMAC", hash: "SHA-256", length: 256 },
    false,
    ["sign"]
  );
}
async function computeBackupMac(payloadJson, passphrase, saltBytes, params, cryptoApi = globalThis.crypto) {
  const safeCrypto = requireCrypto(cryptoApi);
  const macKey = await deriveBackupMacKey(passphrase, saltBytes, params, safeCrypto);
  const signature = await safeCrypto.subtle.sign("HMAC", macKey, encoder.encode(payloadJson));
  return toHex(signature);
}
function normalizePassphrase(passphrase) {
  const clean = (passphrase || "").trim();
  if (clean.length < 8) {
    throw new OtpVaultError("Use a passphrase with at least 8 characters", { code: "PASSPHRASE_TOO_SHORT" });
  }
  return clean;
}
async function deriveVaultKey(passphrase, salt, params = KDF_PARAMS_DEFAULT, cryptoApi = globalThis.crypto) {
  const safeCrypto = requireCrypto(cryptoApi);
  const material = await safeCrypto.subtle.importKey("raw", encoder.encode(passphrase), "PBKDF2", false, ["deriveKey"]);
  return safeCrypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: params.iterations, hash: params.hash },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt", "wrapKey", "unwrapKey"]
  );
}
async function deriveVaultKeyFromPayload(payload, passphrase, cryptoApi = globalThis.crypto) {
  const normalizedPayload = validateEncryptedPayload(payload);
  return deriveVaultKey(
    normalizePassphrase(passphrase),
    fromBase64(normalizedPayload.salt),
    resolveKdfParams(normalizedPayload.kdf),
    requireCrypto(cryptoApi)
  );
}
async function decryptAndNormalize(key, normalizedPayload, safeCrypto) {
  const decrypted = await safeCrypto.subtle.decrypt(
    { name: "AES-GCM", iv: fromBase64(normalizedPayload.iv) },
    key,
    fromBase64(normalizedPayload.data)
  );
  const parsed = JSON.parse(decoder.decode(decrypted));
  return normalizeBackupEntriesStrict(parsed, {
    message: "Decrypted vault entries are invalid",
    code: "VAULT_ENTRIES_INVALID"
  });
}
async function decryptVaultEntriesWithKey(key, payload, cryptoApi = globalThis.crypto) {
  const safeCrypto = requireCrypto(cryptoApi);
  const normalizedPayload = validateEncryptedPayload(payload);
  try {
    return await decryptAndNormalize(key, normalizedPayload, safeCrypto);
  } catch (error) {
    if (error instanceof OtpVaultError) throw error;
    throw new OtpVaultError("Incorrect passphrase or unreadable encrypted data", {
      code: "VAULT_DECRYPT_FAILED",
      cause: error
    });
  }
}
function validateKdfParams(kdf) {
  if (!kdf || typeof kdf !== "object" || Array.isArray(kdf)) {
    throw new OtpVaultError("Encrypted data has an invalid kdf block", { code: "VAULT_FIELDS" });
  }
  if (kdf.algorithm !== "PBKDF2" || kdf.hash !== "SHA-256") {
    throw new OtpVaultError("Encrypted data uses an unsupported KDF", { code: "VAULT_FIELDS" });
  }
  if (!Number.isInteger(kdf.iterations) || kdf.iterations <= 0 || kdf.iterations > KDF_ITERATIONS_CEILING) {
    throw new OtpVaultError("Encrypted data has an invalid kdf block", { code: "VAULT_FIELDS" });
  }
  if (kdf.saltBytes !== void 0 && (!Number.isInteger(kdf.saltBytes) || kdf.saltBytes <= 0)) {
    throw new OtpVaultError("Encrypted data has an invalid kdf block", { code: "VAULT_FIELDS" });
  }
  return kdf;
}
function resolveKdfParams(kdf) {
  if (!kdf) return KDF_PARAMS_LEGACY;
  validateKdfParams(kdf);
  if (kdf.iterations < KDF_PARAMS_LEGACY.iterations) return KDF_PARAMS_LEGACY;
  return kdf;
}
function isLegacyEncryptedPayload(payload) {
  if (!payload || typeof payload !== "object") return false;
  if (!payload.kdf) return true;
  if (typeof payload.kdf !== "object") return true;
  return typeof payload.kdf.iterations !== "number" || payload.kdf.iterations < KDF_PARAMS_LEGACY.iterations;
}
var COMMON_PASSPHRASE_PATTERNS = [
  "password",
  "passwort",
  "passphrase",
  "123456",
  "qwerty",
  "letmein",
  "welcome",
  "iloveyou",
  "admin",
  "dragon",
  "monkey",
  "sunshine",
  "princess",
  "football",
  "master",
  "vault"
];
var STRENGTH_LABELS = ["Very weak", "Weak", "Fair", "Good", "Strong"];
var BACKUP_REMINDER_MS = 30 * 24 * 60 * 60 * 1e3;
function shouldWarnBackup(settings2, entryCount, now = Date.now()) {
  if (!Number.isInteger(entryCount) || entryCount < 1) return false;
  const lastBackupAt = Number(settings2?.lastBackupAt);
  if (!Number.isFinite(lastBackupAt) || lastBackupAt <= 0) return true;
  return now - lastBackupAt > BACKUP_REMINDER_MS;
}
function assessPassphraseStrength(passphrase) {
  const value = String(passphrase || "");
  if (value.length === 0) {
    return { score: 0, label: STRENGTH_LABELS[0], warnings: ["Enter a passphrase"] };
  }
  let score = 0;
  if (value.length >= 8) score = 1;
  if (value.length >= 12) score = 2;
  const characterClasses = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter((pattern) => pattern.test(value)).length;
  if (characterClasses >= 3) score += 1;
  if (characterClasses >= 4) score += 1;
  const warnings = [];
  if (COMMON_PASSPHRASE_PATTERNS.some((pattern) => value.toLowerCase().includes(pattern))) {
    score = Math.max(0, score - 2);
    warnings.push("Avoid common words and patterns");
  }
  if (value.length < 12) {
    warnings.push("Use at least 12 characters for a stronger passphrase");
  }
  score = Math.min(4, score);
  return { score, label: STRENGTH_LABELS[score], warnings };
}
async function encryptEntries(entries2, passphrase, cryptoApi = globalThis.crypto) {
  const safeCrypto = requireCrypto(cryptoApi);
  const normalizedPassphrase = normalizePassphrase(passphrase);
  const salt = safeCrypto.getRandomValues(new Uint8Array(KDF_PARAMS_DEFAULT.saltBytes));
  const iv = safeCrypto.getRandomValues(new Uint8Array(12));
  const key = await deriveVaultKey(normalizedPassphrase, salt, KDF_PARAMS_DEFAULT, safeCrypto);
  const payload = encoder.encode(JSON.stringify(entries2));
  const encrypted = await safeCrypto.subtle.encrypt({ name: "AES-GCM", iv }, key, payload);
  return {
    salt: toBase64(salt),
    iv: toBase64(iv),
    data: toBase64(new Uint8Array(encrypted)),
    kdf: { ...KDF_PARAMS_DEFAULT }
  };
}
function validateEncryptedPayload(payload) {
  if (!payload || typeof payload !== "object") {
    throw new OtpVaultError("Encrypted data is missing or invalid", { code: "VAULT_INVALID" });
  }
  if (typeof payload.salt !== "string" || typeof payload.iv !== "string" || typeof payload.data !== "string") {
    throw new OtpVaultError("Encrypted data is missing required fields", { code: "VAULT_FIELDS" });
  }
  if (payload.kdf !== void 0) {
    validateKdfParams(payload.kdf);
  }
  if (payload.dek !== void 0) {
    const dek = payload.dek;
    if (!dek || typeof dek !== "object" || typeof dek.wrapped !== "string" || typeof dek.iv !== "string") {
      throw new OtpVaultError("Encrypted data has an invalid dek block", { code: "VAULT_FIELDS" });
    }
  }
  return payload;
}
function isDekEncryptedPayload(payload) {
  return Boolean(payload && typeof payload === "object" && payload.kdf && typeof payload.kdf === "object" && payload.kdf.mode === "dek-v1" && payload.dek && typeof payload.dek === "object");
}
async function unwrapDekWithPassphrase(payload, passphrase, cryptoApi = globalThis.crypto) {
  const safeCrypto = requireCrypto(cryptoApi);
  const normalizedPayload = validateEncryptedPayload(payload);
  if (!isDekEncryptedPayload(normalizedPayload)) {
    throw new OtpVaultError("Encrypted data does not contain a DEK envelope", { code: "VAULT_FIELDS" });
  }
  try {
    const wrapKey = await deriveVaultKey(
      normalizePassphrase(passphrase),
      fromBase64(normalizedPayload.salt),
      resolveKdfParams(normalizedPayload.kdf),
      safeCrypto
    );
    return await safeCrypto.subtle.unwrapKey(
      "raw",
      fromBase64(normalizedPayload.dek.wrapped),
      wrapKey,
      { name: "AES-GCM", iv: fromBase64(normalizedPayload.dek.iv) },
      { name: "AES-GCM", length: 256 },
      // extractable + wrapKey: passphrase change (FR11) and re-enrollment must
      // re-wrap this DEK after a reload; it is never exported to storage.
      true,
      ["encrypt", "decrypt", "wrapKey", "unwrapKey"]
    );
  } catch (error) {
    throw new OtpVaultError("Incorrect passphrase or unreadable encrypted data", {
      code: "VAULT_DECRYPT_FAILED",
      cause: error
    });
  }
}
async function wrapDekWithPassphrase(dek, passphrase, salt, params = KDF_PARAMS_DEFAULT, cryptoApi = globalThis.crypto) {
  const safeCrypto = requireCrypto(cryptoApi);
  const wrapKey = await deriveVaultKey(normalizePassphrase(passphrase), salt, params, safeCrypto);
  const iv = safeCrypto.getRandomValues(new Uint8Array(12));
  const wrapped = await safeCrypto.subtle.wrapKey("raw", dek, wrapKey, { name: "AES-GCM", iv });
  return { wrapped: toBase64(new Uint8Array(wrapped)), iv: toBase64(iv) };
}
async function generateVaultDek(cryptoApi = globalThis.crypto) {
  const safeCrypto = requireCrypto(cryptoApi);
  return safeCrypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt", "wrapKey", "unwrapKey"]);
}
async function encryptEntriesWithDek(entries2, dek, envelopeMeta, cryptoApi = globalThis.crypto) {
  const safeCrypto = requireCrypto(cryptoApi);
  const { salt, kdf, dek: dekBlock } = envelopeMeta || {};
  if (typeof salt !== "string" || !kdf || !dekBlock) {
    throw new OtpVaultError("A DEK-mode envelope meta block is required", { code: "VAULT_FIELDS" });
  }
  const iv = safeCrypto.getRandomValues(new Uint8Array(12));
  const payload = encoder.encode(JSON.stringify(entries2));
  const encrypted = await safeCrypto.subtle.encrypt({ name: "AES-GCM", iv }, dek, payload);
  return {
    salt,
    iv: toBase64(iv),
    data: toBase64(new Uint8Array(encrypted)),
    kdf: { ...kdf, mode: "dek-v1" },
    dek: { ...dekBlock }
  };
}
function hasRequiredBackupSecret(secret) {
  if (typeof secret !== "string") return false;
  const normalizedSecret = sanitizeBase32(secret);
  if (!normalizedSecret) return false;
  try {
    return base32ToBytes(normalizedSecret).length > 0;
  } catch {
    return false;
  }
}
function hasRequiredBackupEntryShape(entry) {
  return Boolean(entry) && typeof entry === "object" && typeof entry.id === "string" && entry.id.trim().length > 0 && typeof entry.label === "string" && entry.label.trim().length > 0 && hasRequiredBackupSecret(entry.secret) && Number.isInteger(entry.digits) && Number.isInteger(entry.period) && typeof entry.createdAt === "number" && Number.isFinite(entry.createdAt);
}
function normalizeBackupEntriesStrict(entries2, { message, code }) {
  if (!Array.isArray(entries2) || !entries2.every(hasRequiredBackupEntryShape)) {
    throw new OtpVaultError(message, { code });
  }
  const normalizedEntries = normalizeEntries(entries2);
  if (normalizedEntries.length !== entries2.length) {
    throw new OtpVaultError(message, { code });
  }
  return normalizedEntries;
}
async function decryptVaultEntries(payload, passphrase, cryptoApi = globalThis.crypto) {
  const safeCrypto = requireCrypto(cryptoApi);
  const normalizedPassphrase = normalizePassphrase(passphrase);
  const normalizedPayload = validateEncryptedPayload(payload);
  try {
    if (isDekEncryptedPayload(normalizedPayload)) {
      const dek = await unwrapDekWithPassphrase(normalizedPayload, normalizedPassphrase, safeCrypto);
      return await decryptAndNormalize(dek, normalizedPayload, safeCrypto);
    }
    const key = await deriveVaultKey(
      normalizedPassphrase,
      fromBase64(normalizedPayload.salt),
      resolveKdfParams(normalizedPayload.kdf),
      safeCrypto
    );
    return await decryptAndNormalize(key, normalizedPayload, safeCrypto);
  } catch (error) {
    if (error instanceof OtpVaultError) throw error;
    throw new OtpVaultError("Incorrect passphrase or unreadable encrypted data", {
      code: "VAULT_DECRYPT_FAILED",
      cause: error
    });
  }
}
async function buildBackupEnvelope(payload, encrypted, cryptoApi = globalThis.crypto) {
  return {
    version: BACKUP_VERSION,
    encrypted,
    createdAt: (/* @__PURE__ */ new Date()).toISOString(),
    itemCount: encrypted ? 0 : payload.entries.length,
    checksum: await sha256Hex(JSON.stringify(payload), cryptoApi),
    payload
  };
}
async function createPlainBackup(entries2, cryptoApi = globalThis.crypto) {
  const payload = {
    schemaVersion: 1,
    entries: entries2
  };
  return buildBackupEnvelope(payload, false, cryptoApi);
}
async function createEncryptedBackup(vaultPayload, passphrase, cryptoApi = globalThis.crypto) {
  validateEncryptedPayload(vaultPayload);
  const normalizedPassphrase = normalizePassphrase(passphrase);
  const payload = {
    schemaVersion: 1,
    vault: vaultPayload
  };
  const mac = await computeBackupMac(
    JSON.stringify(payload),
    normalizedPassphrase,
    fromBase64(vaultPayload.salt),
    resolveKdfParams(vaultPayload.kdf),
    cryptoApi
  );
  const envelope = await buildBackupEnvelope(payload, true, cryptoApi);
  return { ...envelope, mac };
}

// lib/biometric.js
var encoder2 = new TextEncoder();
var RP_NAME = "Personal OTP Vault";
var USER_NAME = "otp-vault";
var KEK_INFO = encoder2.encode("2fa-vault-kek-v1");
var CEREMONY_TIMEOUT_MS = 6e4;
var CHALLENGE_BYTES = 32;
var USER_ID_BYTES = 16;
var PRF_SALT_BYTES = 32;
var DEK_BYTES = 32;
function defaultCredentialsApi() {
  return globalThis.navigator?.credentials;
}
function requireCrypto2(cryptoApi = globalThis.crypto) {
  if (!cryptoApi?.subtle || typeof cryptoApi.getRandomValues !== "function") {
    throw new OtpVaultError("Browser crypto support is unavailable", { code: "CRYPTO_UNAVAILABLE" });
  }
  return cryptoApi;
}
function requireCredentials(credentialsApi, method) {
  if (!credentialsApi || typeof credentialsApi[method] !== "function") {
    throw new OtpVaultError("WebAuthn is unavailable in this context", { code: "BIOMETRIC_UNSUPPORTED" });
  }
  return credentialsApi;
}
function randomBytes(length, cryptoApi) {
  return requireCrypto2(cryptoApi).getRandomValues(new Uint8Array(length));
}
function toRawBase64(bytes) {
  if (typeof Buffer !== "undefined") {
    return Buffer.from(bytes).toString("base64");
  }
  let binary = "";
  for (let index = 0; index < bytes.length; index += 1) {
    binary += String.fromCharCode(bytes[index]);
  }
  return btoa(binary);
}
function toB64u(bytes) {
  if (!ArrayBuffer.isView(bytes)) {
    throw new OtpVaultError("Base64url encoding expects bytes", { code: "BIOMETRIC_INVALID_STATE" });
  }
  return toRawBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function fromB64u(value) {
  try {
    if (typeof value !== "string") {
      throw new TypeError("base64url input must be a string");
    }
    const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
    const padded = normalized + "=".repeat((4 - normalized.length % 4) % 4);
    const bytes = typeof Buffer !== "undefined" ? new Uint8Array(Buffer.from(padded, "base64")) : Uint8Array.from(atob(padded), (char) => char.charCodeAt(0));
    if (toB64u(bytes) !== value) {
      throw new Error("value is not canonical base64url");
    }
    return bytes;
  } catch (error) {
    throw new OtpVaultError("Value is not valid base64url", { code: "BIOMETRIC_INVALID_STATE", cause: error });
  }
}
async function prfCapable({
  credentialsApi = defaultCredentialsApi(),
  publicKeyCredential = globalThis.PublicKeyCredential
} = {}) {
  if (!credentialsApi || typeof publicKeyCredential !== "function") {
    return false;
  }
  let platformAuthenticatorAvailable = false;
  try {
    platformAuthenticatorAvailable = await publicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
  } catch {
    platformAuthenticatorAvailable = false;
  }
  if (!platformAuthenticatorAvailable) {
    return false;
  }
  try {
    if (typeof publicKeyCredential.getClientCapabilities !== "function") {
      return true;
    }
    const capabilities = await publicKeyCredential.getClientCapabilities();
    return capabilities?.prf === true;
  } catch {
    return true;
  }
}
function mapCeremonyError(error) {
  if (error instanceof OtpVaultError) return error;
  if (error?.name === "NotAllowedError") {
    return new OtpVaultError("Biometric verification was cancelled or blocked \u2014 use the passphrase to unlock", {
      code: "BIOMETRIC_NOT_ALLOWED",
      cause: error
    });
  }
  if (error?.name === "InvalidStateError") {
    return new OtpVaultError("The authenticator is in an invalid state \u2014 use the passphrase to unlock", {
      code: "BIOMETRIC_INVALID_STATE",
      cause: error
    });
  }
  if (error?.name === "NotSupportedError") {
    return new OtpVaultError("This authenticator does not support PRF-based unlock", {
      code: "BIOMETRIC_UNSUPPORTED",
      cause: error
    });
  }
  return new OtpVaultError("WebAuthn ceremony failed", { code: "BIOMETRIC_CEREMONY_FAILED", cause: error });
}
async function runCreateCeremony({
  rpId,
  credentialsApi = defaultCredentialsApi(),
  cryptoApi = globalThis.crypto
} = {}) {
  const safeCredentials = requireCredentials(credentialsApi, "create");
  const safeCrypto = requireCrypto2(cryptoApi);
  const publicKey = {
    challenge: randomBytes(CHALLENGE_BYTES, safeCrypto),
    rp: { name: RP_NAME, id: rpId },
    user: {
      id: randomBytes(USER_ID_BYTES, safeCrypto),
      name: USER_NAME
    },
    pubKeyCredParams: [
      { type: "public-key", alg: -7 },
      { type: "public-key", alg: -257 }
    ],
    authenticatorSelection: {
      userVerification: "required",
      residentKey: "preferred"
    },
    timeout: CEREMONY_TIMEOUT_MS,
    attestation: "none",
    extensions: { prf: {} }
  };
  let credential;
  try {
    credential = await safeCredentials.create({ publicKey });
  } catch (error) {
    throw mapCeremonyError(error);
  }
  const extensionResults = credential?.getClientExtensionResults?.() ?? {};
  if (extensionResults.prf?.enabled !== true) {
    throw new OtpVaultError("This authenticator cannot provide PRF-based unlock", {
      code: "BIOMETRIC_UNSUPPORTED"
    });
  }
  if (!credential.rawId) {
    throw new OtpVaultError("The authenticator did not return a credential", {
      code: "BIOMETRIC_CEREMONY_FAILED"
    });
  }
  return { credentialId: toB64u(new Uint8Array(credential.rawId)) };
}
async function runAssertCeremony({
  credentialId,
  prfSalt,
  credentialsApi = defaultCredentialsApi(),
  allowEvalFallback = true,
  rpId,
  cryptoApi = globalThis.crypto
} = {}) {
  const safeCredentials = requireCredentials(credentialsApi, "get");
  const safeCrypto = requireCrypto2(cryptoApi);
  if (!credentialId || typeof credentialId !== "string") {
    throw new OtpVaultError("No biometric credential is enrolled", { code: "BIOMETRIC_INVALID_STATE" });
  }
  if (!ArrayBuffer.isView(prfSalt) || prfSalt.byteLength === 0) {
    throw new OtpVaultError("The stored PRF salt is missing", { code: "BIOMETRIC_INVALID_STATE" });
  }
  const idBytes = fromB64u(credentialId);
  const salts = { first: prfSalt };
  const buildOptions = (extensions) => {
    const publicKey = {
      challenge: randomBytes(CHALLENGE_BYTES, safeCrypto),
      allowCredentials: [{ id: idBytes, type: "public-key" }],
      userVerification: "required",
      timeout: CEREMONY_TIMEOUT_MS,
      extensions
    };
    if (rpId !== void 0) {
      publicKey.rpId = rpId;
    }
    return { publicKey };
  };
  let assertion;
  try {
    assertion = await safeCredentials.get(buildOptions({
      prf: { evalByCredential: { [credentialId]: salts } }
    }));
  } catch (error) {
    if (!allowEvalFallback || error?.name !== "NotSupportedError") {
      throw mapCeremonyError(error);
    }
    try {
      assertion = await safeCredentials.get(buildOptions({ prf: { eval: salts } }));
    } catch (retryError) {
      throw mapCeremonyError(retryError);
    }
  }
  const extensionResults = assertion?.getClientExtensionResults?.() ?? {};
  const first = extensionResults.prf?.results?.first;
  if (!first) {
    throw new OtpVaultError("The authenticator did not return PRF output", {
      code: "BIOMETRIC_UNSUPPORTED"
    });
  }
  return { credentialId, prfOutput: new Uint8Array(first) };
}
async function deriveKek(prfOutput, prfSalt, cryptoApi = globalThis.crypto) {
  const safeCrypto = requireCrypto2(cryptoApi);
  try {
    if (!ArrayBuffer.isView(prfOutput) || prfOutput.byteLength < 16) {
      throw new Error("PRF output must be at least 16 bytes");
    }
    const ikm = await safeCrypto.subtle.importKey("raw", prfOutput, "HKDF", false, ["deriveKey"]);
    return await safeCrypto.subtle.deriveKey(
      { name: "HKDF", hash: "SHA-256", salt: prfSalt, info: KEK_INFO },
      ikm,
      { name: "AES-GCM", length: 256 },
      false,
      ["wrapKey", "unwrapKey"]
    );
  } catch (error) {
    throw new OtpVaultError("Could not derive the biometric unlock key", {
      code: "BIOMETRIC_KEY_DERIVATION_FAILED",
      cause: error
    });
  }
}
async function wrapDek(dek, kek, iv, cryptoApi = globalThis.crypto) {
  const safeCrypto = requireCrypto2(cryptoApi);
  try {
    if (!ArrayBuffer.isView(dek) || dek.byteLength !== DEK_BYTES) {
      throw new Error("The vault key must be 256 bits");
    }
    const dekKey = await safeCrypto.subtle.importKey("raw", dek, { name: "AES-GCM" }, true, ["encrypt", "decrypt"]);
    const wrapped = await safeCrypto.subtle.wrapKey("raw", dekKey, kek, { name: "AES-GCM", iv });
    return new Uint8Array(wrapped);
  } catch (error) {
    throw new OtpVaultError("Could not wrap the vault key with the biometric key", {
      code: "BIOMETRIC_KEY_DERIVATION_FAILED",
      cause: error
    });
  }
}
async function unwrapDek(wrapped, iv, kek, cryptoApi = globalThis.crypto) {
  const safeCrypto = requireCrypto2(cryptoApi);
  try {
    return await safeCrypto.subtle.unwrapKey(
      "raw",
      wrapped,
      kek,
      { name: "AES-GCM", iv },
      { name: "AES-GCM", length: 256 },
      // extractable + wrapKey so re-enrollment can re-wrap the held DEK under
      // a new KEK; raw bytes never leave memory and are never persisted.
      true,
      ["encrypt", "decrypt", "wrapKey", "unwrapKey"]
    );
  } catch (error) {
    throw new OtpVaultError("Could not unwrap the vault key with the biometric key", {
      code: "BIOMETRIC_KEY_DERIVATION_FAILED",
      cause: error
    });
  }
}
async function enrollBiometricUnlock({
  rpId,
  credentialsApi = defaultCredentialsApi(),
  cryptoApi = globalThis.crypto
} = {}) {
  const safeCrypto = requireCrypto2(cryptoApi);
  const { credentialId } = await runCreateCeremony({ rpId, credentialsApi, cryptoApi: safeCrypto });
  const prfSalt = randomBytes(PRF_SALT_BYTES, safeCrypto);
  const { prfOutput } = await runAssertCeremony({
    credentialId,
    prfSalt,
    credentialsApi,
    rpId,
    cryptoApi: safeCrypto
  });
  return { credentialId, prfSalt, firstPrfOutput: prfOutput };
}

// extension/popup.js
var STORAGE_KEY = "otp_extension_entries_v3";
var LEGACY_STORAGE_KEY = "otp_extension_entries_v2";
var ENCRYPTED_KEY = "otp_extension_encrypted_v1";
var BIOMETRIC_KEY = "otp_extension_biometric_v1";
var SETTINGS_KEY = "otp_extension_settings_v1";
var UI_KEY = "otp_extension_ui_v1";
var SESSION_UNLOCK_KEY = "otp_extension_session_unlock_v1";
var UNLOCK_GUARD_KEY = "otp_extension_unlock_guard_v1";
var UNDO_TOMBSTONE_KEY = "otp_extension_undo_tombstone_v1";
var UNDO_TOMBSTONE_TTL_MS = 10 * 60 * 1e3;
var UNDO_TOAST_MS = 1e4;
var form = document.getElementById("entry-form");
var labelInput = document.getElementById("label");
var secretInput = document.getElementById("secret");
var tagsInput = document.getElementById("tags");
var digitsInput = document.getElementById("digits");
var periodInput = document.getElementById("period");
var entryTypeSelect = document.getElementById("entry-type");
var counterInput = document.getElementById("counter");
var algorithmSelect = document.getElementById("algorithm");
var qrFileInput = document.getElementById("qr-file");
var searchInput = document.getElementById("search");
var sortSelect = document.getElementById("sort-select");
var pasteUriBtn = document.getElementById("paste-uri");
var toggleFormBtn = document.getElementById("toggle-form");
var lockBtn = document.getElementById("lock-btn");
var statusNode = document.getElementById("status");
var entriesRoot = document.getElementById("entries");
var globalSeconds = document.getElementById("global-seconds");
var globalBar = document.getElementById("global-bar");
var template = document.getElementById("entry-template");
var unlockPanel = document.getElementById("unlock-panel");
var unlockPassphraseInput = document.getElementById("unlock-passphrase");
var unlockBtn = document.getElementById("unlock-btn");
var unlockStatus = document.getElementById("unlock-status");
var encryptToggle = document.getElementById("encrypt-toggle");
var passphraseFields = document.getElementById("passphrase-fields");
var passphraseGuidance = document.getElementById("passphrase-guidance");
var passphraseInput = document.getElementById("passphrase");
var passphraseConfirmInput = document.getElementById("passphrase-confirm");
var changePassphraseBtn = document.getElementById("change-passphrase-btn");
var changePassphraseForm = document.getElementById("change-passphrase-form");
var currentPassphraseInput = document.getElementById("current-passphrase");
var newPassphraseInput = document.getElementById("new-passphrase");
var newPassphraseConfirmInput = document.getElementById("new-passphrase-confirm");
var saveSecurityBtn = document.getElementById("save-security");
var copyHistoryRoot = document.getElementById("copy-history");
var unlockForm = document.getElementById("unlock-form");
var securityForm = document.getElementById("security-form");
var editEntryForm = document.getElementById("edit-entry-form");
var editEntryDialog = document.getElementById("edit-entry-dialog");
var editEntryIdInput = document.getElementById("edit-entry-id");
var editLabelInput = document.getElementById("edit-label");
var editSecretInput = document.getElementById("edit-secret");
var editTagsInput = document.getElementById("edit-tags");
var editDigitsInput = document.getElementById("edit-digits");
var editPeriodInput = document.getElementById("edit-period");
var editCounterInput = document.getElementById("edit-counter");
var editAlgorithmSelect = document.getElementById("edit-algorithm");
var editStatus = document.getElementById("edit-status");
var cancelEditBtn = document.getElementById("cancel-edit");
var saveEditBtn = document.getElementById("save-edit");
var confirmRemoveDialog = document.getElementById("confirm-remove-dialog");
var confirmRemoveMessage = document.getElementById("confirm-remove-message");
var pasteGaBtn = document.getElementById("paste-ga");
var exportBackupBtn = document.getElementById("export-backup");
var migrationPreviewDialog = document.getElementById("migration-preview-dialog");
var migrationPreviewForm = document.getElementById("migration-preview-form");
var migrationPreviewStatus = document.getElementById("migration-preview-status");
var migrationPreviewList = document.getElementById("migration-preview-list");
var importAppsInput = document.getElementById("import-app-file");
var languageSelect = document.getElementById("language-select");
var qrExportDialog = document.getElementById("qr-export-dialog");
var qrExportCanvas = document.getElementById("qr-export-canvas");
var qrExportTitle = document.getElementById("qr-export-title");
var qrExportStatus = document.getElementById("qr-export-status");
var copyQrUriBtn = document.getElementById("copy-qr-uri");
var qrExportUri = "";
var entries = [];
var entryNodes = /* @__PURE__ */ new Map();
var collapsed = false;
var settings = { encrypt: false, sortBy: "alpha", theme: "system", locale: "system" };
var currentPassphrase = "";
var heldDek = null;
var dekEnvelopeMeta = null;
var biometricCapable = false;
var copyHistory = [];
var confirmRemoveCallback = null;
var lastActivity = Date.now();
var migrationPreviewState = null;
var undoTombstone = null;
function applyTheme() {
  const theme = settings.theme || "system";
  if (theme === "light" || theme === "dark") {
    document.documentElement.dataset.theme = theme;
  } else {
    delete document.documentElement.dataset.theme;
  }
}
function applyLocale() {
  setLocale(resolveLocale(settings.locale));
  applyTranslations(document);
  applyUiState();
  renderEntries();
  renderCopyHistory();
  renderBackupReminder();
  renderBiometricControls();
}
initialize();
async function initialize() {
  const stored = await chrome.storage.local.get([STORAGE_KEY, LEGACY_STORAGE_KEY, ENCRYPTED_KEY, SETTINGS_KEY, UI_KEY]);
  settings = { encrypt: false, sortBy: "alpha", autoLockMinutes: 15, timeDriftCheck: false, ...stored[SETTINGS_KEY] || {} };
  collapsed = Boolean(stored[UI_KEY]?.collapsed);
  encryptToggle.checked = settings.encrypt;
  sortSelect.value = settings.sortBy || "alpha";
  const autoLockSelect = document.getElementById("auto-lock-select");
  if (autoLockSelect) autoLockSelect.value = String(settings.autoLockMinutes ?? 15);
  const timeDriftToggle = document.getElementById("time-drift-toggle");
  if (timeDriftToggle) timeDriftToggle.checked = Boolean(settings.timeDriftCheck);
  const themeSelect = document.getElementById("theme-select");
  if (themeSelect) themeSelect.value = settings.theme || "system";
  if (languageSelect) languageSelect.value = settings.locale || "system";
  applyTheme();
  const hasExistingEncryptedVault = Boolean(settings.encrypt && stored[ENCRYPTED_KEY]);
  passphraseFields.classList.toggle("hidden", !settings.encrypt || hasExistingEncryptedVault);
  passphraseGuidance?.classList.toggle("hidden", !hasExistingEncryptedVault);
  applyUiState();
  if (settings.encrypt && stored[ENCRYPTED_KEY]) {
    const cached = await readSessionUnlock(stored[ENCRYPTED_KEY]);
    if (cached) {
      entries = cached.entries;
      currentPassphrase = cached.passphrase;
      if (isDekEncryptedPayload(stored[ENCRYPTED_KEY])) {
        heldDek = cached.keyHandle;
        dekEnvelopeMeta = extractDekEnvelopeMeta(stored[ENCRYPTED_KEY]);
      }
      if (entries.every((entry) => !entry.order)) entries = resequenceEntries(entries);
      setLocked(false);
      await offerUndoFromTombstone();
    } else {
      setLocked(true);
    }
  } else {
    const rawEntries = stored[STORAGE_KEY] ?? stored[LEGACY_STORAGE_KEY];
    entries = normalizeEntries(rawEntries);
    if (entries.every((entry) => !entry.order)) entries = resequenceEntries(entries);
    setLocked(false);
    await offerUndoFromTombstone();
  }
  if (settings.encrypt && stored[ENCRYPTED_KEY]) {
    await reconcileOrphanedBiometricRecord();
  }
  applyLocale();
  bindEvents();
  bindPassphraseStrengthMeters();
  bindAutoLockActivity();
  renderEntries();
  renderCopyHistory();
  renderBackupReminder();
  renderBiometricControls();
  tick();
  setInterval(tick, 1e3);
  prfCapable().then((capable) => {
    biometricCapable = capable;
    renderBiometricControls();
  }).catch(() => {
    biometricCapable = false;
    renderBiometricControls();
  });
}
async function readSessionUnlock(encryptedPayload) {
  try {
    const cached = (await chrome.storage.session.get(SESSION_UNLOCK_KEY))[SESSION_UNLOCK_KEY];
    if (!cached || !cached.keyHandle || typeof cached.passphrase !== "string") return null;
    const entriesDecrypted = await decryptVaultEntriesWithKey(cached.keyHandle, encryptedPayload);
    return { entries: entriesDecrypted, passphrase: cached.passphrase, keyHandle: cached.keyHandle };
  } catch (error) {
    reportError("Session unlock cache miss or invalid", error);
    await chrome.storage.session.remove(SESSION_UNLOCK_KEY);
    return null;
  }
}
async function writeSessionUnlock(encryptedPayload, passphrase, keyHandle) {
  try {
    await chrome.storage.session.set({ [SESSION_UNLOCK_KEY]: { passphrase, keyHandle } });
  } catch (error) {
    reportError("Session unlock cache write failed", error);
  }
}
async function clearSessionUnlock() {
  try {
    await chrome.storage.session.remove(SESSION_UNLOCK_KEY);
  } catch (error) {
    reportError("Session unlock cache clear failed", error);
  }
}
function bytesToBase64(bytes) {
  let text = "";
  for (const byte of bytes) text += String.fromCharCode(byte);
  return btoa(text);
}
function base64ToBytes(value) {
  const text = atob(value);
  const bytes = new Uint8Array(text.length);
  for (let i = 0; i < text.length; i += 1) bytes[i] = text.charCodeAt(i);
  return bytes;
}
async function readBiometricRecord() {
  try {
    const stored = await chrome.storage.local.get(BIOMETRIC_KEY);
    const record = stored[BIOMETRIC_KEY];
    if (!record || typeof record.credentialId !== "string" || typeof record.prfSalt !== "string" || typeof record.wrappedDek !== "string" || typeof record.wrappedIv !== "string") {
      return null;
    }
    return record;
  } catch (error) {
    reportError("Failed to read biometric record", error);
    return null;
  }
}
async function writeBiometricRecord(record) {
  await chrome.storage.local.set({ [BIOMETRIC_KEY]: record });
}
async function removeBiometricRecord() {
  await chrome.storage.local.remove(BIOMETRIC_KEY);
}
function extractDekEnvelopeMeta(payload) {
  if (!isDekEncryptedPayload(payload)) return null;
  return { salt: payload.salt, kdf: { ...payload.kdf }, dek: { ...payload.dek } };
}
async function exportDekRawBytes(dek) {
  return new Uint8Array(await crypto.subtle.exportKey("raw", dek));
}
async function reconcileOrphanedBiometricRecord() {
  const record = await readBiometricRecord();
  if (!record) return;
  let payload = null;
  try {
    const stored = await chrome.storage.local.get(ENCRYPTED_KEY);
    payload = stored[ENCRYPTED_KEY] ?? null;
  } catch {
    payload = null;
  }
  if (isDekEncryptedPayload(payload)) return;
  await removeBiometricRecord();
  renderBiometricControls();
}
async function requirePassphrase(actionLabel) {
  if (currentPassphrase) return currentPassphrase;
  if (!heldDek) return "";
  const candidate = window.prompt(t("ext.passphrasePromptAction", { action: actionLabel }));
  if (!candidate) throw new Error(t("vault.passphraseRequired"));
  const normalized = normalizePassphrase(candidate);
  const stored = await chrome.storage.local.get(ENCRYPTED_KEY);
  const payload = stored[ENCRYPTED_KEY];
  if (!payload || !isDekEncryptedPayload(payload)) {
    throw new Error(t("vault.passphraseRequired"));
  }
  heldDek = await unwrapDekWithPassphrase(payload, normalized);
  dekEnvelopeMeta = extractDekEnvelopeMeta(payload);
  currentPassphrase = normalized;
  await writeSessionUnlock(payload, normalized, heldDek);
  return currentPassphrase;
}
function releasePassphrase(previousPassphrase) {
  if (!previousPassphrase) currentPassphrase = "";
}
async function refreshSessionCacheForDek(payload) {
  if (!heldDek) return;
  await writeSessionUnlock(payload, currentPassphrase, heldDek);
}
function applyUiState() {
  document.body.classList.toggle("collapsed", collapsed);
  toggleFormBtn.textContent = collapsed ? t("ext.show") : t("ext.hide");
}
async function saveUiState() {
  await chrome.storage.local.set({ [UI_KEY]: { collapsed } });
}
function setStatus(node, message, tone = "") {
  node.textContent = message;
  node.classList.remove("error", "success");
  if (tone) node.classList.add(tone);
}
function setMainStatus(message, tone = "") {
  setStatus(statusNode, message, tone);
}
function setUnlockStatus(message, tone = "") {
  setStatus(unlockStatus, message, tone);
}
function lockVault() {
  currentPassphrase = "";
  heldDek = null;
  dekEnvelopeMeta = null;
  if (unlockPassphraseInput) unlockPassphraseInput.value = "";
  setUnlockStatus("");
  entries = [];
  if (settings.clearClipboard) {
    copyHistory = [];
    renderCopyHistory();
  }
  clearSessionUnlock();
  undoTombstone = null;
  purgeUndoTombstone();
  setLocked(true);
  renderEntries();
}
function noteActivity() {
  lastActivity = Date.now();
}
function bindAutoLockActivity() {
  let lastNoted = 0;
  const throttled = () => {
    const now = Date.now();
    if (now - lastNoted < 1e3) return;
    lastNoted = now;
    noteActivity();
  };
  document.addEventListener("pointermove", throttled);
  document.addEventListener("keydown", throttled);
}
async function readUnlockGuard() {
  try {
    const stored = await chrome.storage.local.get(UNLOCK_GUARD_KEY);
    const parsed = stored[UNLOCK_GUARD_KEY];
    return { attempts: Number(parsed?.attempts) || 0, lockedUntil: Number(parsed?.lockedUntil) || 0 };
  } catch {
    return { attempts: 0, lockedUntil: 0 };
  }
}
function writeUnlockGuard(guard) {
  return chrome.storage.local.set({ [UNLOCK_GUARD_KEY]: guard });
}
function unlockBackoffSeconds(attempts) {
  return Math.min(60, 2 ** Math.max(0, attempts - 3));
}
function collectMigrationPayloads(rawText) {
  const uris = extractMigrationUris(rawText);
  if (uris.length === 0) return { payloads: [], warnings: [] };
  const payloads = [];
  const warnings = [];
  for (const uri of uris) {
    try {
      payloads.push(parseMigrationUri(uri).payloadBytes);
    } catch (error) {
      warnings.push(toUserMessage(error, "A migration QR could not be read"));
    }
  }
  return { payloads, warnings };
}
function stageMigrationPayloads(payloadByteArrays, sourceLabel) {
  const stitched = stitchMigrationBatches(payloadByteArrays);
  const warnings = [...stitched.warnings];
  if (stitched.entries.length === 0) {
    throw new Error(t("vault.noImportable", { source: sourceLabel, details: warnings.length ? `: ${warnings.join(" ")}` : "" }));
  }
  const candidates = [];
  let skipped = 0;
  let invalid = 0;
  for (const params of stitched.entries) {
    try {
      const candidate = migrationToEntryCandidates([params])[0];
      const entry = normalizeEntry(candidate);
      if (hasDuplicateEntry(entries, entry) || candidates.some((existing) => existing.secret === entry.secret && existing.label === entry.label)) {
        candidates.push({ ...entry, duplicateHint: true });
        skipped += 1;
        continue;
      }
      candidates.push(entry);
    } catch (error) {
      invalid += 1;
      warnings.push(toUserMessage(error, t("import.mapFailed")));
    }
  }
  openMigrationPreview({ candidates, skipped, invalid, warnings, sourceLabel });
}
function openMigrationPreview(previewResult) {
  migrationPreviewState = previewResult;
  renderMigrationPreview();
  migrationPreviewDialog?.showModal?.();
}
function renderMigrationPreview() {
  if (!migrationPreviewState || !migrationPreviewList) return;
  const { candidates, skipped, invalid, warnings, sourceLabel } = migrationPreviewState;
  let statusText = t("ext.importAppsStatus", { source: sourceLabel, count: candidates.length, plural: candidates.length === 1 ? "y" : "ies" });
  if (skipped > 0) statusText += t("ext.importAppsSkipped", { count: skipped, plural: skipped === 1 ? "" : "s" });
  if (invalid > 0) statusText += t("ext.importAppsInvalid", { count: invalid });
  if (warnings.length > 0) statusText += ` ${warnings.join(" ")}`;
  migrationPreviewStatus.textContent = statusText;
  migrationPreviewList.innerHTML = "";
  candidates.forEach((entry, index) => {
    const row = document.createElement("label");
    row.className = "toggle-row";
    row.dataset.index = String(index);
    const checkbox = document.createElement("input");
    checkbox.type = "checkbox";
    checkbox.className = "migration-include";
    checkbox.checked = !entry.duplicateHint;
    const summaryParts = [entry.label, `${entry.digits} digits`];
    if (entry.type === "hotp") summaryParts.push(`HOTP #${entry.counter}`);
    if (entry.algorithm && entry.algorithm !== "SHA1") summaryParts.push(entry.algorithm.replace(/^SHA/, "SHA-"));
    const text = document.createElement("span");
    text.textContent = entry.duplicateHint ? `${summaryParts.join(" \u2022 ")}${t("ext.alreadyInVaultSuffix")}` : summaryParts.join(" \u2022 ");
    row.append(checkbox, text);
    migrationPreviewList.appendChild(row);
  });
}
async function commitMigrationPreview() {
  if (!migrationPreviewState) return;
  const rows = [...migrationPreviewList.querySelectorAll(".toggle-row")];
  const nextOrder = nextOrderValueFrom(entries);
  const selected = rows.flatMap((row, index) => {
    const checkbox = row.querySelector(".migration-include");
    if (!checkbox?.checked) return [];
    const candidate = migrationPreviewState.candidates[index];
    return [normalizeEntry({ ...candidate, order: nextOrder + index })];
  });
  if (selected.length === 0) throw new Error(t("import.selectAtLeastOne"));
  await replaceEntries([...entries, ...selected]);
  migrationPreviewState = null;
}
async function writeUndoTombstone(items) {
  try {
    if (!settings.encrypt) {
      await chrome.storage.local.set({
        [UNDO_TOMBSTONE_KEY]: { at: Date.now(), indexes: items.map((item) => item.index), entries: items.map((item) => item.entry) }
      });
      return;
    }
    const indexes = items.map((item) => item.index);
    const deletedEntries = items.map((item) => item.entry);
    if (currentPassphrase) {
      const vault = await encryptEntries(deletedEntries, currentPassphrase);
      await chrome.storage.local.set({
        [UNDO_TOMBSTONE_KEY]: { at: Date.now(), indexes, vault }
      });
      return;
    }
    if (heldDek && dekEnvelopeMeta) {
      const dekVault = await encryptEntriesWithDek(deletedEntries, heldDek, dekEnvelopeMeta);
      await chrome.storage.local.set({
        [UNDO_TOMBSTONE_KEY]: { at: Date.now(), indexes, dekVault }
      });
    }
  } catch (error) {
    reportError("Undo tombstone write failed", error);
  }
}
async function purgeUndoTombstone() {
  await chrome.storage.local.remove(UNDO_TOMBSTONE_KEY);
}
async function readLiveUndoTombstone() {
  try {
    const stored = await chrome.storage.local.get(UNDO_TOMBSTONE_KEY);
    const tombstone = stored[UNDO_TOMBSTONE_KEY];
    if (!tombstone || typeof tombstone.at !== "number" || Date.now() - tombstone.at > UNDO_TOMBSTONE_TTL_MS) {
      await purgeUndoTombstone();
      return null;
    }
    let deletedEntries = tombstone.entries || [];
    if (tombstone.dekVault) {
      if (!heldDek) {
        await purgeUndoTombstone();
        return null;
      }
      deletedEntries = await decryptVaultEntriesWithKey(heldDek, tombstone.dekVault);
    } else if (tombstone.vault) {
      deletedEntries = await decryptVaultEntries(tombstone.vault, currentPassphrase);
    }
    if (!Array.isArray(deletedEntries) || deletedEntries.length === 0) {
      await purgeUndoTombstone();
      return null;
    }
    const indexes = Array.isArray(tombstone.indexes) ? tombstone.indexes : [];
    return deletedEntries.map((entry, position) => ({ entry, index: indexes[position] ?? position }));
  } catch (error) {
    reportError("Undo tombstone read failed", error);
    await purgeUndoTombstone();
    return null;
  }
}
async function undoDelete(items) {
  undoTombstone = null;
  await purgeUndoTombstone();
  let reinserted = 0;
  const nextEntries = [...entries];
  for (const { entry, index } of items) {
    if (nextEntries.some((existing) => existing.id === entry.id)) continue;
    nextEntries.splice(Math.min(Math.max(index, 0), nextEntries.length), 0, entry);
    reinserted += 1;
  }
  if (reinserted === 0) {
    setMainStatus(t("ext.undoNothing"), "warning");
    return;
  }
  await replaceEntries(nextEntries);
  setMainStatus(reinserted === 1 ? t("import.restoredOne") : t("import.restoredMany", { count: reinserted }), "success");
}
async function offerUndoDelete(items) {
  await writeUndoTombstone(items);
  undoTombstone = items;
  setMainStatus(items.length === 1 ? t("ext.undoRemovedOne") : t("ext.undoRemovedMany", { count: items.length }), "warning");
  setTimeout(async () => {
    if (undoTombstone === items) {
      undoTombstone = null;
      await purgeUndoTombstone();
    }
  }, UNDO_TOAST_MS);
}
async function offerUndoFromTombstone() {
  if (undoTombstone || !unlockPanel.classList.contains("hidden")) return;
  const items = await readLiveUndoTombstone();
  if (!items) return;
  undoTombstone = items;
  const status = document.getElementById("status");
  if (!status) return;
  status.textContent = items.length === 1 ? t("ext.undoOfferOne") : t("ext.undoOfferMany", { count: items.length });
  status.classList.add("error");
  const undoBtn = document.createElement("button");
  undoBtn.type = "button";
  undoBtn.className = "ghost-btn";
  undoBtn.textContent = t("ext.undoDelete");
  undoBtn.addEventListener("click", async () => {
    undoBtn.remove();
    await undoDelete(items);
  });
  status.appendChild(document.createElement("br"));
  status.appendChild(undoBtn);
  setTimeout(async () => {
    undoBtn.remove();
    if (undoTombstone === items) {
      undoTombstone = null;
      await purgeUndoTombstone();
    }
  }, UNDO_TOMBSTONE_TTL_MS);
}
function parseTraceTimestamp(text) {
  const match = /(?:^|\n)ts=([0-9.]+)/.exec(text || "");
  if (!match) return null;
  const seconds = Number(match[1]);
  return Number.isFinite(seconds) ? seconds * 1e3 : null;
}
async function stampBackupExport(envelope) {
  settings.lastBackupAt = Date.now();
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(JSON.stringify(envelope.payload)));
  settings.lastBackupHash = [...new Uint8Array(digest)].map((part) => part.toString(16).padStart(2, "0")).join("");
  await persistSettings();
}
async function exportBackup() {
  const previousPassphrase = currentPassphrase;
  await requirePassphrase(t("ext.actionExportBackup"));
  try {
    let envelope;
    if (settings.encrypt) {
      if (!currentPassphrase) throw new Error(t("ext.exportNeedsUnlock"));
      const encryptedPayload = await encryptEntries(entries, currentPassphrase);
      envelope = await createEncryptedBackup(encryptedPayload, currentPassphrase);
    } else {
      envelope = await createPlainBackup(entries);
    }
    const blob = new Blob([JSON.stringify(envelope, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "otp-vault-extension-backup.json";
    link.click();
    URL.revokeObjectURL(url);
    await stampBackupExport(envelope);
  } finally {
    releasePassphrase(previousPassphrase);
  }
}
function renderBackupReminder() {
  const line = document.getElementById("last-export-line");
  if (!line) return;
  if (shouldWarnBackup(settings, entries.length)) {
    line.textContent = settings.lastBackupAt ? t("backup.reminderExtensionOld") : entries.length > 0 ? t("backup.reminderExtensionNoExport") : "";
    line.classList.remove("hidden");
    return;
  }
  const lastBackupAt = Number(settings.lastBackupAt);
  if (!Number.isFinite(lastBackupAt) || lastBackupAt <= 0) {
    line.textContent = t("backup.lastExportNever");
    return;
  }
  const days = Math.floor((Date.now() - lastBackupAt) / 864e5);
  const exportAge = days === 0 ? t("backup.lastExportToday") : days === 1 ? t("backup.lastExportOneDay") : t("backup.lastExportDays", { days });
  line.textContent = `${exportAge}${t("backup.lastExportChecksum", { hash: String(settings.lastBackupHash || "").slice(0, 8) })}${t("backup.lastExportShortSuffix")}`;
}
async function checkTimeDrift() {
  if (!settings.timeDriftCheck) return;
  try {
    const response = await fetch("https://www.cloudflare.com/cdn-cgi/trace", { cache: "no-store" });
    const serverMs = parseTraceTimestamp(await response.text());
    const skewMs = Number.isFinite(serverMs) ? Math.abs(Date.now() - serverMs) : null;
    const banner = document.getElementById("drift-banner");
    if (banner) {
      const skewMs2 = skewMs;
      banner.querySelector("#drift-skew").textContent = skewMs2 !== null ? `${(skewMs2 / 1e3).toFixed(1)}s` : "";
      banner.classList.toggle("hidden", !(skewMs2 !== null && skewMs2 > 5e3));
    }
  } catch (error) {
    reportError("Extension time drift check skipped", error);
    document.getElementById("drift-banner")?.classList.add("hidden");
  }
}
function renderPassphraseStrength(input, meterRoot) {
  if (!input || !meterRoot) return;
  const assessment = translateStrengthAssessment(assessPassphraseStrength(input.value));
  meterRoot.classList.toggle("hidden", input.value.length === 0);
  const fill = meterRoot.querySelector(".strength-fill");
  if (fill) fill.dataset.score = String(assessment.score);
  const label = meterRoot.querySelector(".strength-label");
  if (label) label.textContent = assessment.label;
  const warnings = meterRoot.querySelector(".strength-warnings");
  if (warnings) warnings.textContent = assessment.warnings.join(" ");
}
function bindPassphraseStrengthMeters() {
  const unlockMeter = document.getElementById("unlock-passphrase-strength");
  const setMeter = document.getElementById("set-passphrase-strength");
  unlockPassphraseInput?.addEventListener("input", () => renderPassphraseStrength(unlockPassphraseInput, unlockMeter));
  passphraseInput?.addEventListener("input", () => renderPassphraseStrength(passphraseInput, setMeter));
  passphraseConfirmInput?.addEventListener("input", () => renderPassphraseStrength(passphraseConfirmInput, setMeter));
}
async function changeVaultPassphrase(currentPassphraseCandidate, nextPassphraseCandidate, confirmPassphraseCandidate) {
  if (!settings.encrypt) {
    throw new Error(t("ext.changePassphraseNeedsEncryption"));
  }
  const previousPassphrase = currentPassphrase;
  if (!previousPassphrase) {
    await requirePassphrase(t("ext.actionChangePassphrase"));
  }
  if (currentPassphraseCandidate !== currentPassphrase) {
    releasePassphrase(previousPassphrase);
    throw new Error(t("vault.currentIncorrect"));
  }
  if (nextPassphraseCandidate !== confirmPassphraseCandidate) {
    releasePassphrase(previousPassphrase);
    throw new Error(t("vault.confirmationMismatch"));
  }
  const normalizedNext = normalizePassphrase(nextPassphraseCandidate);
  const stored = await chrome.storage.local.get(ENCRYPTED_KEY);
  const payload = stored[ENCRYPTED_KEY];
  if (payload && isDekEncryptedPayload(payload)) {
    try {
      const dek = await unwrapDekWithPassphrase(payload, currentPassphrase);
      const meta = extractDekEnvelopeMeta(payload);
      const nextDekBlock = await wrapDekWithPassphrase(dek, normalizedNext, base64ToBytes(meta.salt), meta.kdf);
      const envelope = await encryptEntriesWithDek(entries, dek, { ...meta, dek: nextDekBlock });
      await chrome.storage.local.set({ [ENCRYPTED_KEY]: envelope });
      heldDek = dek;
      dekEnvelopeMeta = extractDekEnvelopeMeta(envelope);
      currentPassphrase = normalizedNext;
      await writeSessionUnlock(envelope, currentPassphrase, heldDek);
    } finally {
      releasePassphrase(previousPassphrase);
    }
    return;
  }
  currentPassphrase = normalizedNext;
  try {
    await persistEntries();
    await clearSessionUnlock();
  } catch (error) {
    currentPassphrase = previousPassphrase;
    throw error;
  }
  releasePassphrase(previousPassphrase);
}
function setLocked(locked) {
  unlockPanel.classList.toggle("hidden", !locked);
  form.querySelectorAll("input, select, button").forEach((node) => {
    node.disabled = locked;
  });
  qrFileInput.disabled = locked;
  searchInput.disabled = locked;
  sortSelect.disabled = locked;
  pasteUriBtn.disabled = locked;
  lockBtn.disabled = locked || !settings.encrypt;
  changePassphraseBtn.classList.toggle("hidden", !settings.encrypt || locked);
  if (locked) {
    changePassphraseForm.classList.add("hidden");
  }
}
function sortEntries(items) {
  const sorted = [...items];
  if (settings.sortBy === "custom") {
    return sorted.sort((left, right) => (left.order ?? 0) - (right.order ?? 0) || left.label.localeCompare(right.label, void 0, { sensitivity: "base" }));
  }
  if (settings.sortBy === "recent") {
    return sorted.sort((left, right) => right.createdAt - left.createdAt);
  }
  if (settings.sortBy === "period") {
    return sorted.sort((left, right) => left.period - right.period || left.label.localeCompare(right.label, void 0, { sensitivity: "base" }));
  }
  return sorted.sort((left, right) => left.label.localeCompare(right.label, void 0, { sensitivity: "base" }));
}
function filteredEntries() {
  const query = (searchInput.value || "").trim().toLowerCase();
  return sortEntries(entries).filter((entry) => [entry.label, ...entry.tags || []].join(" ").toLowerCase().includes(query));
}
function refreshEntryNode(node, entry) {
  const parts = parseLabelParts(entry.label);
  node.querySelector(".avatar").textContent = getIssuerInitials(entry.label);
  node.querySelector(".issuer").textContent = parts.issuer;
  node.querySelector(".account").textContent = parts.account;
  node.querySelector(".meta").textContent = `${entry.digits} digits \u2022 ${entry.period}s`;
  const algoBadge = node.querySelector(".algo");
  if (algoBadge) {
    const showAlgo = entry.algorithm && entry.algorithm !== "SHA1";
    algoBadge.textContent = showAlgo ? entry.algorithm.replace(/^SHA/, "SHA-") : "";
    algoBadge.classList.toggle("hidden", !showAlgo);
  }
  const counterBadge = node.querySelector(".counter");
  if (counterBadge) {
    const isHotp = entry.type === "hotp";
    counterBadge.textContent = isHotp ? `#${entry.counter}` : "";
    counterBadge.classList.toggle("hidden", !isHotp);
  }
  const tagRoot = node.querySelector(".tags");
  tagRoot.innerHTML = "";
  for (const tag of entry.tags || []) {
    const chip = document.createElement("span");
    chip.className = "tag";
    chip.textContent = tag;
    tagRoot.appendChild(chip);
  }
}
function addCopyHistory(label, code) {
  copyHistory = [
    {
      label,
      code: formatCode(code),
      at: (/* @__PURE__ */ new Date()).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
    },
    ...copyHistory.filter((item) => item.label !== label)
  ].slice(0, 5);
  renderCopyHistory();
}
function renderCopyHistory() {
  if (!copyHistoryRoot) return;
  copyHistoryRoot.innerHTML = "";
  if (copyHistory.length === 0) {
    const empty = document.createElement("div");
    empty.className = "empty-state";
    empty.textContent = "Copied OTPs will appear here.";
    copyHistoryRoot.appendChild(empty);
    return;
  }
  for (const item of copyHistory) {
    const row = document.createElement("div");
    row.className = "history-item";
    const strong = document.createElement("strong");
    strong.textContent = item.label;
    const span = document.createElement("span");
    span.textContent = `${item.code} \u2022 ${item.at}`;
    row.append(strong, span);
    copyHistoryRoot.appendChild(row);
  }
}
function nextOrderValue(items = entries) {
  if (items.length === 0) return 1;
  return Math.max(...items.map((entry) => Number(entry.order) || 0)) + 1;
}
function resequenceEntries(items) {
  return items.map((entry, index) => ({ ...entry, order: index + 1 }));
}
function resequenceIfUnordered(decrypted) {
  return decrypted.every((entry) => !entry.order) ? resequenceEntries(decrypted) : decrypted;
}
async function unlockWithBiometrics() {
  const guard = await readUnlockGuard();
  if (guard.lockedUntil > Date.now()) {
    setUnlockStatus(t("ext.tooManyAttempts", { seconds: Math.ceil((guard.lockedUntil - Date.now()) / 1e3) }), "error");
    return;
  }
  const record = await readBiometricRecord();
  if (!record) {
    setUnlockStatus(t("ext.noBiometricEnrolled"), "error");
    return;
  }
  const stored = await chrome.storage.local.get(ENCRYPTED_KEY);
  const payload = stored[ENCRYPTED_KEY];
  if (!payload || !isDekEncryptedPayload(payload)) {
    await reconcileOrphanedBiometricRecord();
    setUnlockStatus(t("ext.biometricUnavailable"), "error");
    return;
  }
  try {
    const prfSalt = fromB64u(record.prfSalt);
    const { prfOutput } = await runAssertCeremony({ credentialId: record.credentialId, prfSalt });
    const kek = await deriveKek(prfOutput, prfSalt);
    const dek = await unwrapDek(fromB64u(record.wrappedDek), fromB64u(record.wrappedIv), kek);
    const decrypted = await decryptVaultEntriesWithKey(dek, payload);
    heldDek = dek;
    dekEnvelopeMeta = extractDekEnvelopeMeta(payload);
    currentPassphrase = "";
    entries = resequenceIfUnordered(decrypted);
    await writeSessionUnlock(payload, "", heldDek);
    await writeUnlockGuard({ attempts: 0, lockedUntil: 0 });
    setLocked(false);
    renderEntries();
    tick();
    setUnlockStatus(t("unlock.statusBiometricSuccess"), "success");
    setMainStatus(t("ext.unlocked"), "success");
  } catch (error) {
    reportError("Biometric unlock failed", error);
    setUnlockStatus(toUserMessage(error, t("ext.biometricUnlockFailed")), "error");
  }
}
async function enrollVaultBiometrics() {
  if (!settings.encrypt) {
    throw new Error(t("ext.enrollNeedsEncryption"));
  }
  if (!currentPassphrase && !heldDek) {
    throw new Error(t("ext.enrollNeedsUnlock"));
  }
  const stored = await chrome.storage.local.get(ENCRYPTED_KEY);
  const payload = stored[ENCRYPTED_KEY];
  if (payload && !isDekEncryptedPayload(payload) && !currentPassphrase) {
    throw new Error(t("ext.enrollNeedsUnlock"));
  }
  const enrollment = await enrollBiometricUnlock({});
  const prfSalt = enrollment.prfSalt;
  const kek = await deriveKek(enrollment.firstPrfOutput, prfSalt);
  const wrapIv = crypto.getRandomValues(new Uint8Array(12));
  let dek;
  let envelope = null;
  if (payload && isDekEncryptedPayload(payload)) {
    dek = heldDek || await unwrapDekWithPassphrase(payload, currentPassphrase);
    dekEnvelopeMeta = extractDekEnvelopeMeta(payload);
  } else {
    dek = await generateVaultDek();
    const saltBytes = crypto.getRandomValues(new Uint8Array(KDF_PARAMS_DEFAULT.saltBytes));
    const dekBlock = await wrapDekWithPassphrase(dek, currentPassphrase, saltBytes, KDF_PARAMS_DEFAULT);
    envelope = await encryptEntriesWithDek(entries, dek, {
      salt: bytesToBase64(saltBytes),
      kdf: { ...KDF_PARAMS_DEFAULT },
      dek: dekBlock
    });
  }
  const rawDek = await exportDekRawBytes(dek);
  const wrappedDek = await wrapDek(rawDek, kek, wrapIv);
  const record = {
    credentialId: enrollment.credentialId,
    prfSalt: toB64u(prfSalt),
    wrappedDek: toB64u(wrappedDek),
    wrappedIv: toB64u(wrapIv)
  };
  if (envelope) {
    await chrome.storage.local.set({ [ENCRYPTED_KEY]: envelope });
  }
  await writeBiometricRecord(record);
  heldDek = dek;
  if (envelope) {
    dekEnvelopeMeta = extractDekEnvelopeMeta(envelope);
    await refreshSessionCacheForDek(envelope);
  }
  renderBiometricControls();
}
async function disenrollVaultBiometrics() {
  const record = await readBiometricRecord();
  if (!record) {
    setMainStatus(t("settings.biometricNotEnabled"), "error");
    return;
  }
  const confirmed = window.confirm(`${t("settings.biometricDisableTitle")} ${t("settings.biometricDisableText")}`);
  if (!confirmed) return;
  const previousPassphrase = currentPassphrase;
  await requirePassphrase(t("ext.actionDisableBiometric"));
  try {
    const restored = await encryptEntries(entries, currentPassphrase);
    await chrome.storage.local.set({ [ENCRYPTED_KEY]: restored });
    await removeBiometricRecord();
    await clearSessionUnlock();
    heldDek = null;
    dekEnvelopeMeta = null;
    setMainStatus(t("settings.biometricDisabled"), "success");
  } finally {
    releasePassphrase(previousPassphrase);
  }
  renderBiometricControls();
}
function renderBiometricControls() {
  const section = document.getElementById("biometric-settings");
  if (!section) return;
  readBiometricRecord().then((record) => {
    section.classList.toggle("hidden", !biometricCapable);
    const enrollBtn = document.getElementById("enroll-biometric-btn");
    const disenrollBtn = document.getElementById("disenroll-biometric-btn");
    const statusLine = document.getElementById("biometric-status-line");
    if (enrollBtn) {
      enrollBtn.classList.toggle("hidden", !biometricCapable || Boolean(record) || !settings.encrypt);
    }
    if (disenrollBtn) {
      disenrollBtn.classList.toggle("hidden", !biometricCapable || !record);
    }
    if (statusLine) {
      statusLine.textContent = !biometricCapable ? "" : record ? t("settings.extensionBiometricEnrolled") : settings.encrypt ? t("settings.extensionBiometricAvailable") : t("settings.biometricNeedsEncryption");
    }
    const unlockBiometricBtn = document.getElementById("biometric-unlock-btn");
    if (unlockBiometricBtn) {
      unlockBiometricBtn.classList.toggle("hidden", !biometricCapable || !record);
    }
  });
}
function openEditEntryDialog(entry) {
  if (!editEntryDialog?.showModal) return;
  editEntryIdInput.value = entry.id;
  editLabelInput.value = entry.label;
  editSecretInput.value = entry.secret;
  editTagsInput.value = (entry.tags || []).join(", ");
  editDigitsInput.value = String(entry.digits);
  editPeriodInput.value = String(entry.period);
  editAlgorithmSelect.value = entry.algorithm || "SHA1";
  editCounterInput?.classList.toggle("hidden", entry.type !== "hotp");
  if (editCounterInput) editCounterInput.value = String(entry.type === "hotp" ? entry.counter : 0);
  setStatus(editStatus, "");
  editEntryDialog.showModal();
}
async function saveEditedEntry() {
  const id = editEntryIdInput.value;
  const current = entries.find((entry) => entry.id === id);
  if (!current) throw new Error(t("edit.noLongerExists"));
  const updated = normalizeEntry({
    ...current,
    label: editLabelInput.value,
    secret: editSecretInput.value,
    tags: normalizeTags(editTagsInput.value),
    digits: Number(editDigitsInput.value),
    period: Number(editPeriodInput.value),
    algorithm: editAlgorithmSelect.value,
    counter: current.type === "hotp" && editCounterInput ? Number(editCounterInput.value) : current.counter,
    order: current.order
  });
  if (entries.some((entry) => entry.id !== id && entry.secret === updated.secret && entry.digits === updated.digits && entry.period === updated.period)) {
    throw new Error(t("edit.duplicate"));
  }
  await replaceEntries(entries.map((entry) => entry.id === id ? updated : entry));
}
async function moveEntry(entryId, direction) {
  const ordered = sortEntries(entries);
  const index = ordered.findIndex((entry) => entry.id === entryId);
  const nextIndex = index + direction;
  if (index < 0 || nextIndex < 0 || nextIndex >= ordered.length) return;
  [ordered[index], ordered[nextIndex]] = [ordered[nextIndex], ordered[index]];
  await replaceEntries(resequenceEntries(ordered));
}
function showRemoveConfirmation(message) {
  if (!confirmRemoveDialog?.showModal) {
    return Promise.resolve(window.confirm(message));
  }
  confirmRemoveMessage.textContent = message;
  return new Promise((resolve) => {
    confirmRemoveCallback = resolve;
    confirmRemoveDialog.showModal();
  });
}
var entryDragState = null;
function popupCardMidpoints() {
  return [...entriesRoot.querySelectorAll(".entry-card")].map(
    (card) => card.getBoundingClientRect().top + card.offsetHeight / 2
  );
}
function startEntryDrag(event, entry, node) {
  if (settings.sortBy !== "custom" || event.button !== 0 || entryDragState) return;
  const ordered = [...entries].sort((left, right) => compareEntries(left, right, "custom"));
  const fromIndex = ordered.findIndex((item) => item.id === entry.id);
  if (fromIndex < 0 || ordered.length < 2) return;
  event.preventDefault();
  entryDragState = { entryId: entry.id, fromIndex, node };
  node.classList.add("dragging");
  document.body.classList.add("dragging-entry");
  try {
    node.setPointerCapture(event.pointerId);
  } catch {
  }
  node.addEventListener("pointermove", moveEntryDrag);
  node.addEventListener("pointerup", endEntryDrag);
  node.addEventListener("pointercancel", endEntryDrag);
}
function moveEntryDrag(event) {
  if (!entryDragState) return;
  const hovered = [...entriesRoot.querySelectorAll(".entry-card")].find((card) => {
    if (card === entryDragState.node) return false;
    const rect = card.getBoundingClientRect();
    return event.clientY >= rect.top && event.clientY <= rect.bottom;
  });
  [...entriesRoot.querySelectorAll(".entry-card")].forEach((card) => {
    card.classList.toggle("drag-over", card === hovered);
  });
}
async function endEntryDrag(event) {
  const state = entryDragState;
  if (!state) return;
  entryDragState = null;
  state.node.removeEventListener("pointermove", moveEntryDrag);
  state.node.removeEventListener("pointerup", endEntryDrag);
  state.node.removeEventListener("pointercancel", endEntryDrag);
  state.node.classList.remove("dragging");
  document.body.classList.remove("dragging-entry");
  entriesRoot.querySelectorAll(".entry-card").forEach((card) => card.classList.remove("drag-over"));
  const target = computeDropIndex(popupCardMidpoints(), state.fromIndex, event.clientY);
  const ordered = [...entries].sort((left, right) => compareEntries(left, right, "custom"));
  const currentIndex = ordered.findIndex((item) => item.id === state.entryId);
  if (currentIndex < 0) return;
  const [moved] = ordered.splice(currentIndex, 1);
  ordered.splice(Math.min(target, ordered.length), 0, moved);
  try {
    await replaceEntries(resequenceEntries(ordered));
    setMainStatus(t("entries.manualOrderUpdated"), "success");
  } catch (error) {
    reportError("Extension drag reorder failed", error);
    setMainStatus(toUserMessage(error, t("vault.reorderFailed")), "error");
  }
}
function createEntryNode(entry) {
  const node = template.content.firstElementChild.cloneNode(true);
  refreshEntryNode(node, entry);
  const dragHandle = node.querySelector(".drag-handle");
  if (dragHandle) {
    dragHandle.classList.toggle("hidden", settings.sortBy !== "custom");
    dragHandle.addEventListener("pointerdown", (event) => {
      startEntryDrag(event, entry, node);
    });
  }
  node.querySelector(".copy").addEventListener("click", async () => {
    try {
      const otp = node.dataset.otp;
      if (!otp) return;
      await navigator.clipboard.writeText(otp);
      navigator.vibrate?.(20);
      addCopyHistory(entry.label, otp);
      setMainStatus(t("ext.copiedIssuer", { issuer: parseLabelParts(entry.label).issuer }), "success");
      await consumeHotpCounter(entry);
    } catch (error) {
      reportError("Extension copy failed", error);
      setMainStatus(toUserMessage(error, t("vault.copyFailedShort")), "error");
    }
  });
  async function consumeHotpCounter(currentEntry) {
    if (currentEntry.type !== "hotp") return;
    try {
      await replaceEntries(entries.map((item) => item.id === currentEntry.id ? { ...item, counter: item.counter + 1 } : item));
    } catch (error) {
      reportError("HOTP counter persist failed (copy)", error);
      setMainStatus(t("ext.counterSaveFailed"), "error");
    }
  }
  node.querySelector(".edit")?.addEventListener("click", () => {
    openEditEntryDialog(entry);
  });
  node.querySelector(".qr")?.addEventListener("click", () => {
    openQrExport(entry);
  });
  node.querySelector(".move-up")?.addEventListener("click", async () => {
    try {
      settings.sortBy = "custom";
      sortSelect.value = "custom";
      await persistSettings();
      await moveEntry(entry.id, -1);
      setMainStatus(t("entries.manualOrderUpdated"), "success");
    } catch (error) {
      reportError("Extension move up failed", error);
      setMainStatus(toUserMessage(error, "Could not reorder entry"), "error");
    }
  });
  node.querySelector(".move-down")?.addEventListener("click", async () => {
    try {
      settings.sortBy = "custom";
      sortSelect.value = "custom";
      await persistSettings();
      await moveEntry(entry.id, 1);
      setMainStatus(t("entries.manualOrderUpdated"), "success");
    } catch (error) {
      reportError("Extension move down failed", error);
      setMainStatus(toUserMessage(error, "Could not reorder entry"), "error");
    }
  });
  node.querySelector(".remove").addEventListener("click", async () => {
    try {
      const confirmed = await showRemoveConfirmation(t("ext.removeConfirm", { label: entry.label }));
      if (!confirmed) return;
      const index = entries.findIndex((item) => item.id === entry.id);
      await replaceEntries(entries.filter((item) => item.id !== entry.id));
      setMainStatus(t("ext.removedEntry"), "success");
      if (index >= 0) await offerUndoDelete([{ entry, index }]);
    } catch (error) {
      reportError("Extension remove failed", error);
      setMainStatus(toUserMessage(error, t("vault.removeFailed")), "error");
    }
  });
  return node;
}
function renderEntries() {
  if (!unlockPanel.classList.contains("hidden")) {
    entriesRoot.innerHTML = `<div class="empty-state">${t("ext.locked")}</div>`;
    return;
  }
  const visible = filteredEntries();
  if (visible.length === 0) {
    entriesRoot.innerHTML = `<div class="empty-state">${t("ext.noEntries")}</div>`;
    return;
  }
  entriesRoot.innerHTML = "";
  const fragment = document.createDocumentFragment();
  for (const entry of visible) {
    let node = entryNodes.get(entry.id);
    if (!node) {
      node = createEntryNode(entry);
      entryNodes.set(entry.id, node);
    }
    refreshEntryNode(node, entry);
    const dragHandle = node.querySelector(".drag-handle");
    if (dragHandle) dragHandle.classList.toggle("hidden", settings.sortBy !== "custom");
    fragment.appendChild(node);
  }
  for (const [id] of entryNodes) {
    if (!entries.some((entry) => entry.id === id)) entryNodes.delete(id);
  }
  entriesRoot.appendChild(fragment);
}
async function updateEntryNode(entry, now) {
  const node = entryNodes.get(entry.id);
  if (!node) return;
  try {
    let code;
    if (entry.type === "hotp") {
      node.querySelector(".seconds").textContent = t("ext.hotpCounterBadge", { counter: entry.counter });
      node.querySelector(".bar").style.transform = "scaleX(1)";
      const hotpRing = node.querySelector(".ring-progress");
      if (hotpRing) hotpRing.style.strokeDashoffset = "0";
      node.classList.toggle("urgent", false);
      code = await generateHotp(entry.secret, entry.counter, entry.digits, entry.algorithm);
    } else {
      const remaining = entry.period - now % entry.period;
      code = await generateTotp(entry.secret, entry.digits, entry.period, now, entry.algorithm);
      node.querySelector(".seconds").textContent = t("ext.secondsBadge", { seconds: remaining });
      node.querySelector(".bar").style.transform = `scaleX(${remaining / entry.period})`;
      const ring = node.querySelector(".ring-progress");
      if (ring) ring.style.strokeDashoffset = String(100 - remaining / entry.period * 100);
      node.classList.toggle("urgent", remaining <= 10);
    }
    node.dataset.otp = code;
    node.querySelector(".code").textContent = formatCode(code);
  } catch (error) {
    reportError("Extension OTP generation failed", error);
    node.querySelector(".code").textContent = t("entries.invalidShort");
    node.dataset.otp = "";
  }
}
function updateGlobalTimer(now) {
  const visible = filteredEntries();
  const period = visible.length > 0 ? Math.min(...visible.map((entry) => entry.period)) : 30;
  const remaining = period - now % period;
  globalSeconds.textContent = `${remaining}s`;
  globalBar.style.transform = `scaleX(${remaining / period})`;
}
async function tick() {
  const now = Math.floor(Date.now() / 1e3);
  updateGlobalTimer(now);
  const vaultLocked = !unlockPanel.classList.contains("hidden");
  if (settings.encrypt && settings.autoLockMinutes > 0 && !vaultLocked && Date.now() - lastActivity >= settings.autoLockMinutes * 6e4) {
    lockVault();
    return;
  }
  if (vaultLocked) {
    const guard = await readUnlockGuard();
    const remainingMs = guard.lockedUntil - Date.now();
    unlockBtn.disabled = remainingMs > 0;
    if (remainingMs > 0) {
      setUnlockStatus(`Too many failed attempts \u2014 unlock available in ${Math.ceil(remainingMs / 1e3)}s`, "error");
    } else if (unlockStatus.classList.contains("error") && unlockStatus.textContent.startsWith("Too many failed attempts")) {
      setUnlockStatus("");
    }
    return;
  }
  await Promise.all(filteredEntries().map((entry) => updateEntryNode(entry, now)));
}
async function snapshotVaultArtifacts() {
  const stored = await chrome.storage.local.get([STORAGE_KEY, LEGACY_STORAGE_KEY, ENCRYPTED_KEY]);
  return {
    plain: stored[STORAGE_KEY] ?? null,
    legacyPlain: stored[LEGACY_STORAGE_KEY] ?? null,
    encrypted: stored[ENCRYPTED_KEY] ?? null
  };
}
async function restoreVaultArtifacts(snapshot) {
  const updates = {};
  const removes = [];
  if (snapshot.plain === null) {
    removes.push(STORAGE_KEY);
  } else {
    updates[STORAGE_KEY] = snapshot.plain;
  }
  if (snapshot.legacyPlain === null) {
    removes.push(LEGACY_STORAGE_KEY);
  } else {
    updates[LEGACY_STORAGE_KEY] = snapshot.legacyPlain;
  }
  if (snapshot.encrypted === null) {
    removes.push(ENCRYPTED_KEY);
  } else {
    updates[ENCRYPTED_KEY] = snapshot.encrypted;
  }
  if (Object.keys(updates).length > 0) await chrome.storage.local.set(updates);
  if (removes.length > 0) await chrome.storage.local.remove(removes);
}
async function saveEncryptedEntries(payloadEntries, passphrase) {
  const encryptedPayload = await encryptEntries(payloadEntries, passphrase);
  await chrome.storage.local.set({ [ENCRYPTED_KEY]: encryptedPayload });
  await chrome.storage.local.remove([STORAGE_KEY, LEGACY_STORAGE_KEY]);
}
async function persistEntries() {
  const previousArtifacts = await snapshotVaultArtifacts();
  try {
    if (settings.encrypt) {
      if (heldDek) {
        const stored = await chrome.storage.local.get(ENCRYPTED_KEY);
        const payload = stored[ENCRYPTED_KEY];
        if (!payload || !isDekEncryptedPayload(payload) || !dekEnvelopeMeta) {
          throw new Error(t("ext.envelopeMissing"));
        }
        const envelope = await encryptEntriesWithDek(entries, heldDek, dekEnvelopeMeta);
        await chrome.storage.local.set({ [ENCRYPTED_KEY]: envelope });
        await chrome.storage.local.remove([STORAGE_KEY, LEGACY_STORAGE_KEY]);
        await refreshSessionCacheForDek(envelope);
        return;
      }
      if (!currentPassphrase) throw new Error(t("ext.encryptionRequiresUnlock"));
      await saveEncryptedEntries(entries, currentPassphrase);
      return;
    }
    await chrome.storage.local.set({ [STORAGE_KEY]: entries });
    await chrome.storage.local.remove(ENCRYPTED_KEY);
    await removeBiometricRecord();
    heldDek = null;
    dekEnvelopeMeta = null;
  } catch (error) {
    await restoreVaultArtifacts(previousArtifacts);
    throw error;
  }
}
async function persistSettings() {
  await chrome.storage.local.set({ [SETTINGS_KEY]: settings });
}
async function replaceEntries(nextEntries) {
  const previousEntries = entries;
  entries = normalizeEntries(nextEntries);
  if (entries.every((entry) => !entry.order)) entries = resequenceEntries(entries);
  try {
    await persistEntries();
  } catch (error) {
    entries = previousEntries;
    renderEntries();
    await tick();
    throw error;
  }
  renderEntries();
  await tick();
}
async function addEntry(input) {
  const entry = normalizeEntry({ ...input, order: nextOrderValue() });
  if (hasDuplicateEntry(entries, entry)) throw new Error(t("ext.accountExists"));
  await replaceEntries([...entries, entry]);
}
async function importFromQrFile(file) {
  if (typeof BarcodeDetector !== "function") {
    throw new Error(t("ext.qrNeedsBarcodeDetector"));
  }
  const bitmap = await createImageBitmap(file);
  const detector = new BarcodeDetector({ formats: ["qr_code"] });
  const results = await detector.detect(bitmap);
  bitmap.close();
  if (!results.length || !results[0].rawValue) {
    throw new Error(t("ext.qrNotDetected"));
  }
  const uri = extractOtpAuthUri(results[0].rawValue);
  if (!uri) {
    throw new Error(t("ext.qrNoOtpUri"));
  }
  return normalizeEntry({ ...parseOtpAuthUri(uri), order: nextOrderValue() });
}
async function importThirdPartyFile(file) {
  if (file.size > MAX_IMPORT_FILE_BYTES) {
    throw new Error(t("import.fileTooLarge"));
  }
  const text = await file.text();
  const result = parseThirdPartyImport(text);
  const warnings = [...result.warnings];
  const candidates = [];
  let skipped = 0;
  let invalid = 0;
  for (const candidate of result.entries) {
    try {
      const entry = normalizeEntry(candidate);
      const isDuplicate = hasDuplicateEntry(entries, entry) || candidates.some((existing) => existing.secret === entry.secret && existing.label === entry.label);
      if (isDuplicate) {
        candidates.push({ ...entry, duplicateHint: true });
        skipped += 1;
        continue;
      }
      candidates.push(entry);
    } catch (error) {
      invalid += 1;
      warnings.push(toUserMessage(error, t("import.mapFailed")));
    }
  }
  if (candidates.length === 0) {
    throw new Error(t("vault.noImportable", { source: result.format, details: warnings.length ? `: ${warnings.join(" ")}` : "" }));
  }
  openMigrationPreview({ candidates, skipped, invalid, warnings, sourceLabel: result.format });
}
async function openQrExport(entry) {
  if (!qrExportDialog || !qrExportCanvas) return;
  qrExportUri = buildOtpAuthUri(entry);
  qrExportTitle.textContent = `${parseLabelParts(entry.label).issuer} \u2014 ${t("qr.heading")}`;
  setStatus(qrExportStatus, "");
  try {
    await import_qrcode.default.toCanvas(qrExportCanvas, qrExportUri, {
      width: 220,
      margin: 2,
      color: { dark: "#111318", light: "#ffffff" }
    });
    qrExportDialog.showModal();
  } catch (error) {
    reportError("Extension QR export failed", error);
    setMainStatus(toUserMessage(error, t("qr.renderFailed")), "error");
  }
}
function bindEvents() {
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      await addEntry({
        label: labelInput.value,
        secret: secretInput.value,
        tags: normalizeTags(tagsInput.value),
        type: entryTypeSelect?.value || "totp",
        counter: entryTypeSelect?.value === "hotp" ? Number(counterInput?.value || 0) : 0,
        algorithm: algorithmSelect?.value || "SHA1",
        digits: Number(digitsInput.value),
        period: Number(periodInput.value)
      });
      form.reset();
      tagsInput.value = "";
      digitsInput.value = "6";
      periodInput.value = "30";
      counterInput?.classList.add("hidden");
      setMainStatus(t("add.entryAdded"), "success");
    } catch (error) {
      reportError("Extension manual entry failed", error);
      setMainStatus(toUserMessage(error, t("vault.addFailed")), "error");
    }
  });
  entryTypeSelect?.addEventListener("change", () => {
    counterInput?.classList.toggle("hidden", entryTypeSelect.value !== "hotp");
  });
  qrFileInput.addEventListener("change", async () => {
    const [file] = qrFileInput.files || [];
    if (!file) return;
    try {
      const entry = await importFromQrFile(file);
      if (hasDuplicateEntry(entries, entry)) throw new Error(t("ext.accountExists"));
      await replaceEntries([...entries, entry]);
      setMainStatus(t("ext.importedQr"), "success");
    } catch (error) {
      reportError("Extension QR import failed", error);
      setMainStatus(toUserMessage(error, t("ext.qrImportFailed")), "error");
    } finally {
      qrFileInput.value = "";
    }
  });
  pasteUriBtn.addEventListener("click", async () => {
    try {
      let hasClipboardRead = await chrome.permissions.contains({ permissions: ["clipboardRead"] });
      if (!hasClipboardRead) {
        hasClipboardRead = await chrome.permissions.request({ permissions: ["clipboardRead"] });
      }
      if (!hasClipboardRead) {
        throw new Error(t("ext.clipboardDenied"));
      }
      const text = await navigator.clipboard.readText();
      const migration = collectMigrationPayloads(text);
      if (migration.payloads.length > 0) {
        stageMigrationPayloads(migration.payloads, "Clipboard");
        return;
      }
      const uri = extractOtpAuthUri(text);
      if (!uri) throw new Error(t("ext.noClipboardUri"));
      const entry = normalizeEntry({ ...parseOtpAuthUri(uri), order: nextOrderValue() });
      if (hasDuplicateEntry(entries, entry)) throw new Error(t("ext.accountExists"));
      await replaceEntries([...entries, entry]);
      setMainStatus(t("ext.importedUri"), "success");
    } catch (error) {
      reportError("Extension clipboard import failed", error);
      setMainStatus(toUserMessage(error, t("ext.uriImportFailed")), "error");
    }
  });
  pasteGaBtn?.addEventListener("click", async () => {
    try {
      let hasClipboardRead = await chrome.permissions.contains({ permissions: ["clipboardRead"] });
      if (!hasClipboardRead) {
        hasClipboardRead = await chrome.permissions.request({ permissions: ["clipboardRead"] });
      }
      if (!hasClipboardRead) {
        throw new Error(t("ext.clipboardDeniedGa"));
      }
      const text = await navigator.clipboard.readText();
      const migration = collectMigrationPayloads(text);
      if (migration.payloads.length === 0) {
        throw new Error(migration.warnings[0] || t("ext.noClipboardGa"));
      }
      stageMigrationPayloads(migration.payloads, "Google Authenticator");
    } catch (error) {
      reportError("Extension GA import failed", error);
      setMainStatus(toUserMessage(error, t("import.gaFailed")), "error");
    }
  });
  migrationPreviewForm?.addEventListener("submit", async (event) => {
    if (event.submitter?.value !== "accept") return;
    event.preventDefault();
    try {
      await commitMigrationPreview();
      migrationPreviewDialog?.close("accept");
      setMainStatus(t("ext.imported"), "success");
    } catch (error) {
      reportError("Extension GA preview commit failed", error);
      setMainStatus(toUserMessage(error, t("import.commitFailed")), "error");
    }
  });
  migrationPreviewDialog?.addEventListener("close", () => {
    migrationPreviewState = null;
  });
  importAppsInput?.addEventListener("change", async () => {
    const [file] = importAppsInput.files || [];
    if (!file) return;
    setMainStatus(t("import.appsReading"));
    try {
      await importThirdPartyFile(file);
    } catch (error) {
      reportError("Extension Aegis/2FAS import failed", error);
      setMainStatus(toUserMessage(error, t("import.appsFileFailed")), "error");
    } finally {
      importAppsInput.value = "";
    }
  });
  copyQrUriBtn?.addEventListener("click", async () => {
    if (!qrExportUri) return;
    try {
      await navigator.clipboard.writeText(qrExportUri);
      setStatus(qrExportStatus, t("qr.copiedUri"), "success");
    } catch (error) {
      reportError("Extension QR URI copy failed", error);
      setStatus(qrExportStatus, toUserMessage(error, t("toast.copyFailed")), "error");
    }
  });
  qrExportDialog?.addEventListener("close", () => {
    qrExportUri = "";
    setStatus(qrExportStatus, "");
  });
  exportBackupBtn?.addEventListener("click", async () => {
    try {
      await exportBackup();
      renderBackupReminder();
      setMainStatus(t("settings.exportBackupDone"), "success");
    } catch (error) {
      reportError("Extension backup export failed", error);
      setMainStatus(toUserMessage(error, t("settings.exportBackupFailed")), "error");
    }
  });
  document.getElementById("check-drift-btn")?.addEventListener("click", async () => {
    if (!settings.timeDriftCheck) {
      setMainStatus(t("settings.driftCheckFirst"), "warning");
      return;
    }
    await checkTimeDrift();
    setMainStatus(t("settings.driftCheckDone"), "success");
  });
  document.getElementById("drift-dismiss")?.addEventListener("click", () => {
    document.getElementById("drift-banner")?.classList.add("hidden");
  });
  searchInput.addEventListener("input", () => {
    renderEntries();
    tick();
  });
  sortSelect.addEventListener("change", async () => {
    settings.sortBy = sortSelect.value;
    await persistSettings();
    renderEntries();
    tick();
  });
  toggleFormBtn.addEventListener("click", async () => {
    collapsed = !collapsed;
    applyUiState();
    await saveUiState();
  });
  encryptToggle.addEventListener("change", () => {
    passphraseFields.classList.toggle("hidden", !encryptToggle.checked);
  });
  changePassphraseBtn?.addEventListener("click", () => {
    changePassphraseForm.classList.toggle("hidden");
    currentPassphraseInput.value = "";
    newPassphraseInput.value = "";
    newPassphraseConfirmInput.value = "";
  });
  changePassphraseForm?.addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      await changeVaultPassphrase(
        currentPassphraseInput.value.trim(),
        newPassphraseInput.value.trim(),
        newPassphraseConfirmInput.value.trim()
      );
      changePassphraseForm.classList.add("hidden");
      currentPassphraseInput.value = "";
      newPassphraseInput.value = "";
      newPassphraseConfirmInput.value = "";
      setMainStatus(t("settings.extensionPassphraseUpdated"), "success");
    } catch (error) {
      reportError("Extension change passphrase failed", error);
      setMainStatus(toUserMessage(error, t("settings.updateFailed")), "error");
    }
  });
  securityForm?.addEventListener("submit", async (event) => {
    event.preventDefault();
    const previousSettings = { ...settings };
    const previousPassphrase = currentPassphrase;
    let previousArtifacts;
    try {
      previousArtifacts = await snapshotVaultArtifacts();
      settings.encrypt = encryptToggle.checked;
      const autoLockSelect = document.getElementById("auto-lock-select");
      if (autoLockSelect) settings.autoLockMinutes = Number(autoLockSelect.value) || 0;
      const timeDriftToggle = document.getElementById("time-drift-toggle");
      if (timeDriftToggle) settings.timeDriftCheck = timeDriftToggle.checked;
      const themeSelect = document.getElementById("theme-select");
      if (themeSelect) {
        settings.theme = themeSelect.value;
        applyTheme();
      }
      if (languageSelect) {
        settings.locale = languageSelect.value;
        applyLocale();
      }
      if (settings.encrypt) {
        let nextPassphrase = currentPassphrase;
        if (!nextPassphrase) {
          if (previousSettings.encrypt) {
            passphraseInput.value = "";
            passphraseConfirmInput.value = "";
            await persistSettings();
            renderBiometricControls();
            setMainStatus(t("settings.extensionStatusEncryptedSaved"), "success");
            return;
          }
          const first = passphraseInput.value.trim();
          const second = passphraseConfirmInput.value.trim();
          if (first !== second) throw new Error(t("vault.confirmationMismatch"));
          nextPassphrase = normalizePassphrase(first);
        }
        currentPassphrase = nextPassphrase;
        await saveEncryptedEntries(entries, currentPassphrase);
      } else {
        currentPassphrase = "";
        heldDek = null;
        dekEnvelopeMeta = null;
        await clearSessionUnlock();
        await removeBiometricRecord();
        await chrome.storage.local.set({ [STORAGE_KEY]: entries });
        await chrome.storage.local.remove(ENCRYPTED_KEY);
      }
      await persistSettings();
      passphraseInput.value = "";
      passphraseConfirmInput.value = "";
      lockBtn.disabled = !settings.encrypt;
      changePassphraseBtn.classList.toggle("hidden", !settings.encrypt || !unlockPanel.classList.contains("hidden"));
      const encryptedVaultExists = Boolean(settings.encrypt && (currentPassphrase || previousArtifacts?.encrypted));
      passphraseFields.classList.toggle("hidden", !settings.encrypt || encryptedVaultExists);
      passphraseGuidance?.classList.toggle("hidden", !encryptedVaultExists);
      setMainStatus(
        encryptedVaultExists ? t("settings.extensionStatusEncryptedGuidance") : settings.encrypt ? t("settings.extensionStatusEncryptedSaved") : t("settings.extensionStatusPlain"),
        "success"
      );
      renderBiometricControls();
    } catch (error) {
      settings = previousSettings;
      currentPassphrase = previousPassphrase;
      if (previousArtifacts) await restoreVaultArtifacts(previousArtifacts);
      encryptToggle.checked = settings.encrypt;
      passphraseFields.classList.toggle("hidden", !settings.encrypt);
      lockBtn.disabled = !settings.encrypt;
      changePassphraseBtn.classList.toggle("hidden", !settings.encrypt || !unlockPanel.classList.contains("hidden"));
      reportError("Extension save security failed", error);
      setMainStatus(toUserMessage(error, t("settings.extensionSaveFailed")), "error");
    }
  });
  lockBtn.addEventListener("click", () => {
    if (!settings.encrypt) {
      setMainStatus(t("ext.lockNeedsEncryption"), "error");
      return;
    }
    lockVault();
  });
  document.getElementById("biometric-unlock-btn")?.addEventListener("click", () => {
    unlockWithBiometrics();
  });
  document.getElementById("enroll-biometric-btn")?.addEventListener("click", async () => {
    try {
      await enrollVaultBiometrics();
      setMainStatus(t("settings.biometricEnabled"), "success");
    } catch (error) {
      reportError("Biometric enrollment failed", error);
      setMainStatus(toUserMessage(error, t("vault.biometricEnrollmentFailed")), "error");
      renderBiometricControls();
    }
  });
  document.getElementById("disenroll-biometric-btn")?.addEventListener("click", async () => {
    try {
      await disenrollVaultBiometrics();
    } catch (error) {
      reportError("Biometric disenroll failed", error);
      setMainStatus(toUserMessage(error, t("vault.biometricDisenrollFailed")), "error");
    }
  });
  let unlockInFlight = false;
  unlockForm?.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (unlockInFlight) return;
    unlockInFlight = true;
    try {
      const guard = await readUnlockGuard();
      const now = Date.now();
      if (guard.lockedUntil > now) {
        setUnlockStatus(t("ext.tooManyAttempts", { seconds: Math.ceil((guard.lockedUntil - now) / 1e3) }), "error");
        return;
      }
      unlockBtn.disabled = true;
      try {
        const stored = await chrome.storage.local.get(ENCRYPTED_KEY);
        const payload = stored[ENCRYPTED_KEY];
        const candidate = unlockPassphraseInput.value;
        let keyHandle;
        if (isDekEncryptedPayload(payload)) {
          heldDek = await unwrapDekWithPassphrase(payload, normalizePassphrase(candidate));
          dekEnvelopeMeta = extractDekEnvelopeMeta(payload);
          keyHandle = heldDek;
          entries = resequenceIfUnordered(await decryptVaultEntriesWithKey(heldDek, payload));
        } else {
          heldDek = null;
          dekEnvelopeMeta = null;
          keyHandle = await deriveVaultKeyFromPayload(payload, normalizePassphrase(candidate));
          entries = resequenceIfUnordered(await decryptVaultEntries(payload, candidate));
        }
        currentPassphrase = normalizePassphrase(candidate);
        if (isLegacyEncryptedPayload(payload)) {
          await persistEntries();
        }
        await writeSessionUnlock(payload, currentPassphrase, keyHandle);
        await writeUnlockGuard({ attempts: 0, lockedUntil: 0 });
        unlockPassphraseInput.value = "";
        setLocked(false);
        renderEntries();
        tick();
        setUnlockStatus(t("unlock.extensionStatusSuccess"), "success");
        setMainStatus(t("ext.unlocked"), "success");
      } catch (error) {
        const attempts = guard.attempts + 1;
        const backoff = unlockBackoffSeconds(attempts);
        await writeUnlockGuard({ attempts, lockedUntil: attempts >= 3 ? now + backoff * 1e3 : 0 });
        const suffix = attempts >= 3 ? t("ext.lockedForSuffix", { seconds: backoff }) : "";
        reportError("Extension unlock failed", error);
        setUnlockStatus(toUserMessage(error, t("ext.incorrectPassphrase")) + suffix, "error");
      } finally {
        unlockBtn.disabled = false;
      }
    } finally {
      unlockInFlight = false;
    }
  });
  cancelEditBtn.addEventListener("click", () => {
    editEntryDialog.close("cancel");
  });
  editEntryForm?.addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      await saveEditedEntry();
      editEntryDialog.close("accept");
      setMainStatus(t("entries.updated"), "success");
    } catch (error) {
      setStatus(editStatus, toUserMessage(error, t("vault.updateFailed")), "error");
    }
  });
  confirmRemoveDialog?.addEventListener("close", () => {
    if (!confirmRemoveCallback) return;
    const accepted = confirmRemoveDialog.returnValue === "accept";
    confirmRemoveCallback(accepted);
    confirmRemoveCallback = null;
  });
}
