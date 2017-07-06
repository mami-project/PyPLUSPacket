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

def _get_u32(s):
	"""
	Returns s -> u32
	"""

	return struct.unpack(_fmt_u32, s)


def _get_u64(s):
	"""
	Returns s -> u64
	"""

	return struct.unpack(_fmt_u64, s)


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

	return _get_u64(bytes[_magic_pos[0] : _magic_pos[1]]) >> _magic_shift


def get_flags(buf):
	"""
	Returns the flags as ORed bits.
	"""

	return _get_u64(bytes[_magic_pos[0] : _magic_pos[1]]) & _flags_mask


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


class	Packet():

	def __init__(self):
		"""
		Creates a zero packet.
		"""

		# Initialize all the fields to None
		self.PSN = None
		self.PSE = None
		self.CAT = None
		self.PCF_Integrity = None
		self.PCF_Value = None
		self.PCF_Len = None
		self.L = None
		self.R = None
		self.S = None
		self.X = None
		self.Payload = None

		self.Magic = _default_magic


	def from_bytes(self, bytes):
		"""
		Parses a packet from bytes
		"""

		if len(bytes) < _min_packet_len:
			raise ValueError("Minimum length of a PLUS packet is 20 bytes.")


		magicAndFlags = _get_u64(bytes[_magic_pos[0] : _magic_pos[1]])

		magic = magicAndFlags >> _magic_shift

		if magic != self.Magic:
			raise ValueError("Invalid Magic value.")

		flags = magicAndFlags & _flags_mask

		self.L = bool(flags & _l_mask)
		self.R = bool(flags & _r_mask)
		self.S = bool(flags & _s_mask)
		self.X = bool(flags & _x_mask)

		self.CAT = _get_u64(bytes[_cat_pos[0] : _cat_pos[1]])
		self.PSN = _get_u32(bytes[_psn_pos[0] : _psn_pos[1]])
		self.PSE = _get_u32(bytes[_pse_pos[0] : _pse_pos[1]])

		if not self.X:
			self.Payload = bytes[_min_packet_len:]
		else:
			raise ValueError("Extended packets not implemented yet.")

		
	def to_bytes(self):
		"""
		Converts the packet to bytes.
		"""

		pass
