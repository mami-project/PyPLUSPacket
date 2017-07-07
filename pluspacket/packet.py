import struct


_fmt_u64 = ">Q"
_fmt_u32 = ">L"
_magic_shift = 4
_flags_mask = 0x0F
_default_magic = 0xd8007ff
_min_packet_len = 20
_l_mask = 0x08
_r_mask = 0x04
_s_mask = 0x02
_x_mask = 0x01
_cat_pos = (4, 12)
_psn_pos = (12, 16)
_pse_pos = (16, 20)
_magic_pos = (0, 4)
_udp_header_len = 8

PCF_INTEGRITY_FULL = 0x03
PCF_INTEGRITY_HALF = 0x02
PCF_INTEGRITY_QUARTER = 0x01
PCF_INTEGRITY_ZERO = 0x00


def _get_u32(s):
	"""
	Returns s -> u32
	"""

	return struct.unpack(_fmt_u32, s)[0]


def _get_u64(s):
	"""
	Returns s -> u64
	"""

	return struct.unpack(_fmt_u64, s)[0]


def _put_u64(i, buf):
	"""
	Writes an u64
	"""

	buf += struct.pack(_fmt_u64, i)


def _put_u32(i, buf):
	"""
	Writes an u32
	"""

	buf += struct.pack(_fmt_u32, i)


def get_psn(buf):
	"""
	Extracts PSN out of a buffer. It's the caller's responsibility
	to make sure that buffer is large enough. 
	"""

	return _get_u32(buf[_psn_pos[0] : _psn_pos[1]])


def get_pse(buf):
	"""
	Extracts PSE out of a buffer. It's the caller's responsibility
	to make sure that buffer is large enough. 
	"""

	return _get_u32(buf[_pse_pos[0] : _pse_pos[1]])


def get_cat(buf):
	"""
	Extracts CAT out of a buffer. It's the caller's responsibility
	to make sure that buffer is large enough. 
	"""

	return _get_u64(buf[_cat_pos[0] : _cat_pos[1]])


def get_magic(buf):
	"""
	Extracts Magic out of a buffer. It's the caller's responsibility
	to make sure that buffer is large enough. 
	"""

	return _get_u32(buf[_magic_pos[0] : _magic_pos[1]]) >> _magic_shift


def get_flags(buf):
	"""
	Returns the flags as ORed bits.
	"""

	return _get_u32(buf[_magic_pos[0] : _magic_pos[1]]) & _flags_mask


def get_l(buf):
	"""
	Returns True if L is set, otherwise False
	"""

	return bool(get_flags(buf) & _l_mask)


def get_r(buf):
	"""
	Returns True if R is set, otherwise False
	"""

	return bool(get_flags(buf) & _r_mask)


def get_s(buf):
	"""
	Returns True if S is set, otherwise False
	"""

	return bool(get_flags(buf) & _s_mask)


def get_x(buf):
	"""
	Returns True if X is set, otherwise False
	"""

	return bool(get_flags(buf) & _x_mask)


def is_extended_packet(buf):
	"""
	Just an alias for get_x.
	"""

	return get_x(buf)


def parse_packet(buf):
	"""
	Parses a packet completely.
	"""

	return Packet().from_bytes(buf)


def detect_plus_in_udp(buf):
	"""
	Tries to detect the presence of a PLUS header in UDP (incl. header)
	"""

	if len(buf) < _udp_header_len:
		raise ValueError("Buffer too small. UDP header is at least 8 bytes long.")

	udp_payload = buf[_udp_header_len:]

	return detect_plus(udp_payload)


def detect_plus(buf):
	"""
	Tries to detect the presence of a PLUS header in payload (excl. UDP header)
	"""
	
	if len(buf) < _min_packet_len:
		# Technically the magic value could be present here but if the packet
		# is this small then there can't be a complete basic header present and 
		# this is best counted as 'not plus'.
		return False

	magic = get_magic(buf)

	return magic == _default_magic


def _any(xs):
	for x in xs:
		if x:
			return True

	return False

def new_basic_packet(l, r, s, cat, psn, pse, payload):
	p = Packet()

	p.l = l
	p.r = r
	p.s = s
	p.cat = cat
	p.psn = psn
	p.pse = pse
	p.payload = payload
	p.x = False

	return p


class	Packet():

	def __init__(self):
		"""
		Creates a zero packet.
		"""

		# Initialize all the fields to None
		self.psn = None
		self.pse = None
		self.cat = None
		self.pcf_integrity = None
		self.pcf_value = None
		self.pcf_len = None
		self.pcf_type = None
		self.l = None
		self.r = None
		self.s = None
		self.x = None
		self.payload = None

		self.magic = _default_magic


	def is_valid(self):
		"""
		Returns true if the packet's attributes/fields are in a valid state.
		"""

		if _any		([	self.psn == None, self.pse == None,
							self.cat == None, self.magic == None,
							self.l == None, self.r == None,
							self.s == None, self.x == None]):

			return False

		if not self.x:
			return True

		if self.pcf_type == None:
			return False

		if self.pcf_type == 0xFF:
			if _any ([	self.pcf_integrity != None,
							self.pcf_len != None,
							self.pcf_value != None]):
			
				return False

		if _any ([	self.pcf_integrity == None,
						self.pcf_len == None,
						self.pcf_value == None]):

			return False


		if self.pcf_len != len(self.pcf_value):
			return False

		if self.pcf_len > 63:
			return False

		if self.pcf_integrity < 0 or self.pcf_integrity > 3:
			return False

		return True


	def from_bytes(self, bytes):
		"""
		Parses a packet from bytes.
		"""

		if len(bytes) < _min_packet_len:
			raise ValueError("Minimum length of a PLUS packet is 20 bytes.")


		magicAndFlags = _get_u64(bytes[_magic_pos[0] : _magic_pos[1]])

		magic = magicAndFlags >> _magic_shift

		if magic != _default_magic:
			raise ValueError("Invalid Magic value.")

		self.magic = magic

		flags = magicAndFlags & _flags_mask

		self.l = bool(flags & _l_mask)
		self.r = bool(flags & _r_mask)
		self.s = bool(flags & _s_mask)
		self.x = bool(flags & _x_mask)

		self.cat = _get_u64(bytes[_cat_pos[0] : _cat_pos[1]])
		self.psn = _get_u32(bytes[_psn_pos[0] : _psn_pos[1]])
		self.pse = _get_u32(bytes[_pse_pos[0] : _pse_pos[1]])

		if not self.x:
			self.payload = bytes[_min_packet_len:]
		else:
			self._extended(bytes[_min_packet_len:])

		return self


	def _extended(self, buf):
		"""
		Internal. Continues parsing extended headers.
		"""

		if len(buf) < 1:
			raise ValueError("Extended header must have PCF_TYPE")

		pcf_type = buf[0]

		if pcf_type == 0xFF:
			# This means no pcf_integry, pcf_len, pcf_value is present.
			self.payload = buf[1:]
			self.pcf_type = pcf_type
		else:
			if pcf_type == 0x00:
				# One additional pcf_type byte
				buf = buf[1:]

				if len(buf) == 0:
					raise ValueError("Missing additional PCF_TYPE byte")

				pcf_type = buf[0] << 8
			
			buf = buf[1:]

			if len(buf) == 0:
				raise ValueError("Missing PCF_LEN and PCF_INTEGRITY")

			pcf_leni = buf[0]

			pcf_len = pcf_leni >> 2
			pcf_integrity = pcf_leni & 0x03

			buf = buf[1:]

			if len(buf) < pcf_len:
				raise ValueError("Incomplete PCF_VALUE")

			pcf_value = buf[:pcf_len]

			payload = buf[pcf_len:]

			self.pcf_len = pcf_len
			self.pcf_integrity = pcf_integrity
			self.pcf_value = pcf_value
			self.payload = payload

		
	def to_bytes(self):
		"""
		Unparses the packet to bytes.
		"""

		if not self.is_valid():
			raise ValueError("Internal state is not valid!")

		buf = bytearray()

		magicAndFlags = self.magic << 4

		if self.l: magicAndFlags |= _l_mask
		if self.r: magicAndFlags |= _r_mask
		if self.s: magicAndFlags |= _s_mask
		if self.x: magicAndFlags |= _x_mask

		_put_u32(magicAndFlags, buf)
		_put_u64(self.cat, buf)
		_put_u32(self.psn, buf)
		_put_u32(self.pse, buf)

		if not self.x:
			buf += self.payload
			return buf

		if self.pcf_type == 0xFF:
			buf.append(0xFF)
			buf += self.payload
			return buf

		if self.pcf_type & 0x00FF == 0:
			pcf_type = self.pcf_type >> 8
			buf.append(0x00)
			buf.append(pcf_type)

		buf.append(self.pcf_len << 6 | self.pcf_integrity)
		buf += self.pcf_value
		buf += self.payload

		return buf
