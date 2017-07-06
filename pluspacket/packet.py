

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

		self.Magic = 0xd8007ff

	def from_bytes(self, bytes):
		"""
		Parses a packet from bytes
		"""

		if len(bytes) < 20:
			raise ValueError("Minimum length of a PLUS packet is 20 bytes.")

		pass

		
	def to_bytes(self):
		"""
		Converts the packet to bytes.
		"""

		pass
