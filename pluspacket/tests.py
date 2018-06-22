import unittest
import packet

class TestDummy(unittest.TestCase):

	def test_dummy(self):
		self.assertEqual(True, True)


class TestBasicPacket(unittest.TestCase):
	"""
	Basic packet & helpers tests.
	"""

	def test_too_small_packet(self):
		"""
		Tests if too small packets are rejected due to the
		minimum length requirement.
		"""

		with self.assertRaises(ValueError):
			packet.parse_packet([10])


	def test_get_cat(self):
		"""
		Tests if the CAT is read correctly.
		"""

		buf = bytes([	0x00, 0x00, 0x00, 0x00,
							0x01, 0x02, 0x03, 0x04, 
							0x05, 0x06, 0x07, 0x08])

		expected = 0x0102030405060708

		self.assertEqual(packet.get_cat(buf), expected)


	def test_get_magic(self):
		"""
		Tests if the Magic is read correctly.
		"""

		buf = bytes([	0x12, 0x23, 0x34, 0x81])

		expected = 0x1223348

		self.assertEqual(packet.get_magic(buf), expected)


	def test_get_flags(self):
		"""
		Tests if the Flags are read correctly.
		"""

		buf = bytes([	0x12, 0x23, 0x34, 0x8B])

		expected = 0xB

		self.assertEqual(packet.get_flags(buf), expected)


	def test_get_psn(self):
		"""
		Tests if the PSN is read correctly.
		"""

		buf = bytes([	0x00, 0x00, 0x00, 0x00,
							0x00, 0x00, 0x00, 0x00,
							0x00, 0x00, 0x00, 0x00,
							0x12, 0x34, 0x56, 0x78])

		expected = 0x12345678

		self.assertEqual(packet.get_psn(buf), expected)


	def test_get_pse(self):
		"""
		Tests if the PSE is read correctly.
		"""

		buf = bytes([	0x00, 0x00, 0x00, 0x00,
							0x00, 0x00, 0x00, 0x00,
							0x00, 0x00, 0x00, 0x00,
							0x00, 0x00, 0x00, 0x00,
							0x12, 0x34, 0x56, 0x78])

		expected = 0x12345678

		self.assertEqual(packet.get_pse(buf), expected)


	def test_get_lrsx(self):
		"""
		Tests if get_l/r/s/x work correctly.
		"""

		buf = bytes([	0x00, 0x00, 0x00, 0xB])
		
		self.assertEqual(packet.get_l(buf), True)
		self.assertEqual(packet.get_r(buf), False)
		self.assertEqual(packet.get_s(buf), True)
		self.assertEqual(packet.get_x(buf), True)

		buf = bytes([	0x00, 0x00, 0x00, 0x04])

		self.assertEqual(packet.get_l(buf), not True)
		self.assertEqual(packet.get_r(buf), not False)
		self.assertEqual(packet.get_s(buf), not True)
		self.assertEqual(packet.get_x(buf), not True)


	def test_detect_plus(self):
		"""
		Tests if detect_plus works correctly.
		"""

		# magic := 0xd8007ff
		buf = bytes([	0xD8, 0x00, 0x7F, 0xFB,
							0x11, 0x11, 0x11, 0x11,
							0x11, 0x11, 0x11, 0x11,
							0x22, 0x22, 0x22, 0x22,
							0x33, 0x33, 0x33, 0x33])

		self.assertEqual(packet.detect_plus(buf), True)

		buf = bytes([	0xD7, 0x00, 0x7F, 0xFB,
							0x11, 0x11, 0x11, 0x11,
							0x11, 0x11, 0x11, 0x11,
							0x22, 0x22, 0x22, 0x22,
							0x33, 0x33, 0x33, 0x33])

		self.assertEqual(packet.detect_plus(buf), False)

		buf = bytes([	0xD8, 0x00, 0x7F, 0xFB,
							0x11, 0x11, 0x11, 0x11,
							0x11, 0x11, 0x11,
							0x22, 0x22, 0x22, 0x22,
							0x33, 0x33, 0x33, 0x33])

		self.assertEqual(packet.detect_plus(buf), False)


	def test_detect_plus_in_udp(self):
		"""
		Tests if detect_plus_in_udp works correctly.
		"""

		buf = bytes([	0x00, 0x00, 0x00, 0x00,
							0x00, 0x00, 0x00, 0x00,
							0xD8, 0x00, 0x7F, 0xFB,
							0x11, 0x11, 0x11, 0x11,
							0x11, 0x11, 0x11, 0x11,
							0x22, 0x22, 0x22, 0x22,
							0x33, 0x33, 0x33, 0x33])

		self.assertEqual(packet.detect_plus_in_udp(buf), True)

		buf = bytes([	0xD8, 0x00, 0x7F, 0xFB,
							0x11, 0x11, 0x11, 0x11,
							0x11, 0x11, 0x11, 0x11,
							0x22, 0x22, 0x22, 0x22,
							0x33, 0x33, 0x33, 0x33])

		self.assertEqual(packet.detect_plus_in_udp(buf), False)

		buf = bytes([	0x00, 0x00, 0x00, 0x00])

		with self.assertRaises(ValueError):
			self.assertEqual(packet.detect_plus_in_udp(buf), False)


	def test_invalid_magic(self):
		"""
		Tests parsing when magic is invalid.
		"""

		buf = bytes([
			0x18, 0x00, 0x7F, 0xFA, #magic + flags
			0x12, 0x34, 0x56, 0x78, #cat
			0x21, 0x43, 0x65, 0x87,
			0x87, 0x65, 0x43, 0x21, #psn
			0x11, 0x22, 0x33, 0x44, #pse
			0x01, 0x02, 0x03, 0x04, #payload
			0x10, 0x20, 0x30, 0x40, #payload
			0x99, 0x90, 0x99, 0x90])	

		with self.assertRaises(ValueError):
			plus_packet = packet.parse_packet(buf)


	def test_parse_packet_1(self):
		"""
		Tests parsing a basic packet.
		"""

		buf = bytes([
			0xD8, 0x00, 0x7F, 0xFA, #magic + flags
			0x12, 0x34, 0x56, 0x78, #cat
			0x21, 0x43, 0x65, 0x87,
			0x87, 0x65, 0x43, 0x21, #psn
			0x11, 0x22, 0x33, 0x44, #pse
			0x01, 0x02, 0x03, 0x04, #payload
			0x10, 0x20, 0x30, 0x40, #payload
			0x99, 0x90, 0x99, 0x90])

		l = True
		r = False
		s = True

		cat = 0x1234567821436587
		psn = 0x87654321
		pse = 0x11223344

		payload = bytes([
			0x01, 0x02, 0x03, 0x04,
			0x10, 0x20, 0x30, 0x40,
			0x99, 0x90, 0x99, 0x90])

		plus_packet = packet.parse_packet(buf)

		self.assertEqual(plus_packet.l, l)
		self.assertEqual(plus_packet.r, r)
		self.assertEqual(plus_packet.s, s)
		self.assertEqual(plus_packet.x, False)
		self.assertEqual(plus_packet.cat, cat)
		self.assertEqual(plus_packet.psn, psn)
		self.assertEqual(plus_packet.pse, pse)
		self.assertEqual(plus_packet.payload, payload)
		self.assertEqual(plus_packet.is_valid(), True)


class TestExtendedPacket(unittest.TestCase):
	"""
	Tests for extended packets.
	"""
	
	def test_parse_packet_1(self):
		"""
		Tests parsing an extended packet.
		"""

		buf = bytes([
			0xD8, 0x00, 0x7F, 0xFF, # magic + flags (x bit set)
			0x12, 0x34, 0x56, 0x78, # cat
			0x12, 0x34, 0x56, 0x78, # cat..
			0x13, 0x11, 0x11, 0x11, # psn
			0x23, 0x22, 0x22, 0x22, # pse
			0x01, 0x1B, # PCF Type := 0x01,
			# PCF Len 6, PCF I = 11b,
			0x01, 0x02, 0x03, 0x04,
			0x05, 0x06, # 6 bytes PCF value
			0x99, 0x98, 0x97, 0x96]) # 4 bytes payload

		l = True
		r = True
		s = True
		cat = 0x1234567812345678
		psn = 0x13111111
		pse = 0x23222222
		pcf_type = 0x01
		pcf_len = 0x06
		pcf_integrity = 0x03
		pcf_value = bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06])
		payload = bytes([0x99, 0x98, 0x97, 0x96])

		plus_packet = packet.parse_packet(buf)

		self.assertEqual(plus_packet.l, l)
		self.assertEqual(plus_packet.r, r)
		self.assertEqual(plus_packet.s, s)
		self.assertEqual(plus_packet.x, True)
		self.assertEqual(plus_packet.cat, cat)
		self.assertEqual(plus_packet.psn, psn)
		self.assertEqual(plus_packet.pse, pse)
		self.assertEqual(plus_packet.payload, payload)
		self.assertEqual(plus_packet.pcf_type, pcf_type)
		self.assertEqual(plus_packet.pcf_value, pcf_value)
		self.assertEqual(plus_packet.pcf_integrity, pcf_integrity)
		self.assertEqual(plus_packet.is_valid(), True)


	def test_parse_packet_2(self):
		"""
		Tests parsing an extended packet.
		"""

		buf = bytes([
			0xD8, 0x00, 0x7F, 0xFF, # magic + flags (x bit set)
			0x12, 0x34, 0x56, 0x78, # cat
			0x12, 0x34, 0x56, 0x78, # cat..
			0x13, 0x11, 0x11, 0x11, # psn
			0x23, 0x22, 0x22, 0x22, # pse
			0x00, 0x01, 0x00, # PCF Type := 0x0100,
			# PCF Len := 0, PCF I := 00b,
			0x01, 0x02, 0x03, 0x04,
			0x05, 0x06, # 
			0x99, 0x98, 0x97, 0x96]) # 10 bytes payload

		l = True
		r = True
		s = True
		cat = 0x1234567812345678
		psn = 0x13111111
		pse = 0x23222222
		pcf_type = 0x0100
		pcf_len = 0x00
		pcf_integrity = 0x00
		pcf_value = bytes([])
		payload = bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x99, 0x98, 0x97, 0x96])

		plus_packet = packet.parse_packet(buf)

		self.assertEqual(plus_packet.l, l)
		self.assertEqual(plus_packet.r, r)
		self.assertEqual(plus_packet.s, s)
		self.assertEqual(plus_packet.x, True)
		self.assertEqual(plus_packet.cat, cat)
		self.assertEqual(plus_packet.psn, psn)
		self.assertEqual(plus_packet.pse, pse)
		self.assertEqual(plus_packet.payload, payload)
		self.assertEqual(plus_packet.pcf_type, pcf_type)
		self.assertEqual(plus_packet.pcf_value, pcf_value)
		self.assertEqual(plus_packet.pcf_integrity, pcf_integrity)
		self.assertEqual(plus_packet.is_valid(), True)


	def test_parse_packet_3(self):
		"""
		Tests parsing an extended packet.
		"""

		buf = bytes([
			0xD8, 0x00, 0x7F, 0xFF, # magic + flags (x bit set)
			0x12, 0x34, 0x56, 0x78, # cat
			0x12, 0x34, 0x56, 0x78, # cat..
			0x13, 0x11, 0x11, 0x11, # psn
			0x23, 0x22, 0x22, 0x22, # pse
			0xFF, 0x01, 0x00, # PCF Type := 0xFF,
			# PCF Len := 0, PCF I := 00b,
			0x01, 0x02, 0x03, 0x04,
			0x05, 0x06, # 
			0x99, 0x98, 0x97, 0x96]) # 10 bytes payload

		l = True
		r = True
		s = True
		cat = 0x1234567812345678
		psn = 0x13111111
		pse = 0x23222222
		pcf_type = 0xFF
		pcf_len = None
		pcf_integrity = None
		pcf_value = None
		payload = bytes([0x01, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x99, 0x98, 0x97, 0x96])

		plus_packet = packet.parse_packet(buf)

		self.assertEqual(plus_packet.l, l)
		self.assertEqual(plus_packet.r, r)
		self.assertEqual(plus_packet.s, s)
		self.assertEqual(plus_packet.x, True)
		self.assertEqual(plus_packet.cat, cat)
		self.assertEqual(plus_packet.psn, psn)
		self.assertEqual(plus_packet.pse, pse)
		self.assertEqual(plus_packet.payload, payload)
		self.assertEqual(plus_packet.pcf_type, pcf_type)
		self.assertEqual(plus_packet.pcf_value, pcf_value)
		self.assertEqual(plus_packet.pcf_integrity, pcf_integrity)
		self.assertEqual(plus_packet.is_valid(), True)


	def test_parse_packet_4(self):
		"""
		Tests parsing an extended packet.
		"""

		buf = bytes([
			0xD8, 0x00, 0x7F, 0xFF, # magic + flags (x bit set)
			0x12, 0x34, 0x56, 0x78, # cat
			0x12, 0x34, 0x56, 0x78, # cat..
			0x13, 0x11, 0x11, 0x11, # psn
			0x23, 0x22, 0x22, 0x22, # pse
			0x00, 0x00, 0x00, # PCF Type := 0x0000,
			# PCF Len := 0, PCF I := 00b,
			0x01, 0x02, 0x03, 0x04,
			0x05, 0x06, # 
			0x99, 0x98, 0x97, 0x96]) # 10 bytes payload

		l = True
		r = True
		s = True
		cat = 0x1234567812345678
		psn = 0x13111111
		pse = 0x23222222
		pcf_type = 0x0000
		pcf_len = 0x00
		pcf_integrity = 0x00
		pcf_value = bytes([])
		payload = bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x99, 0x98, 0x97, 0x96])

		plus_packet = packet.parse_packet(buf)

		self.assertEqual(plus_packet.l, l)
		self.assertEqual(plus_packet.r, r)
		self.assertEqual(plus_packet.s, s)
		self.assertEqual(plus_packet.x, True)
		self.assertEqual(plus_packet.cat, cat)
		self.assertEqual(plus_packet.psn, psn)
		self.assertEqual(plus_packet.pse, pse)
		self.assertEqual(plus_packet.payload, payload)
		self.assertEqual(plus_packet.pcf_type, pcf_type)
		self.assertEqual(plus_packet.pcf_value, pcf_value)
		self.assertEqual(plus_packet.pcf_integrity, pcf_integrity)
		self.assertEqual(plus_packet.is_valid(), True)


	def test_parse_packet_5(self):
		"""
		Tests parsing an extended packet.
		"""

		buf = bytes([
			0xD8, 0x00, 0x7F, 0xFF, # magic + flags (x bit set)
			0x12, 0x34, 0x56, 0x78, # cat
			0x12, 0x34, 0x56, 0x78, # cat..
			0x13, 0x11, 0x11, 0x11, # psn
			0x23, 0x22, 0x22, 0x22, # pse
			0x00, 0xFF, 0x1B, # PCF Type := 0xFF00,
			# PCF Len 6, PCF I = 11b,
			0x01, 0x02, 0x03, 0x04,
			0x05, 0x06, # 6 bytes PCF value
			0x99, 0x98, 0x97, 0x96]) # 4 bytes payload

		l = True
		r = True
		s = True
		cat = 0x1234567812345678
		psn = 0x13111111
		pse = 0x23222222
		pcf_type = 0xFF00
		pcf_len = 0x06
		pcf_integrity = 0x03
		pcf_value = bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06])
		payload = bytes([0x99, 0x98, 0x97, 0x96])

		plus_packet = packet.parse_packet(buf)

		self.assertEqual(plus_packet.l, l)
		self.assertEqual(plus_packet.r, r)
		self.assertEqual(plus_packet.s, s)
		self.assertEqual(plus_packet.x, True)
		self.assertEqual(plus_packet.cat, cat)
		self.assertEqual(plus_packet.psn, psn)
		self.assertEqual(plus_packet.pse, pse)
		self.assertEqual(plus_packet.payload, payload)
		self.assertEqual(plus_packet.pcf_type, pcf_type)
		self.assertEqual(plus_packet.pcf_value, pcf_value)
		self.assertEqual(plus_packet.pcf_integrity, pcf_integrity)
		self.assertEqual(plus_packet.is_valid(), True)


	def test_parse_packet_6(self):
		"""
		Tests parsing an extended packet.
		"""

		buf = bytes([
			0xD8, 0x00, 0x7F, 0xF1, # magic + flags (x bit set)
			0x12, 0x34, 0x56, 0x78, # cat
			0x12, 0x34, 0x56, 0x71, # cat..
			0x13, 0x11, 0x11, 0x12, # psn
			0x23, 0x22, 0x22, 0x23, # pse
			0x00, 0x00, 0x1B, # PCF Type := 0x00,
			# PCF Len 6, PCF I = 11b,
			0x01, 0x02, 0x03, 0x04,
			0x05, 0x06, # 6 bytes PCF value
			0x99, 0x98, 0x97, 0x96]) # 4 bytes payload

		l = False
		r = False
		s = False
		cat = 0x1234567812345671
		psn = 0x13111112
		pse = 0x23222223
		pcf_type = 0x00
		pcf_len = 0x06
		pcf_integrity = 0x03
		pcf_value = bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06])
		payload = bytes([0x99, 0x98, 0x97, 0x96])

		plus_packet = packet.parse_packet(buf)

		self.assertEqual(plus_packet.l, l)
		self.assertEqual(plus_packet.r, r)
		self.assertEqual(plus_packet.s, s)
		self.assertEqual(plus_packet.x, True)
		self.assertEqual(plus_packet.cat, cat)
		self.assertEqual(plus_packet.psn, psn)
		self.assertEqual(plus_packet.pse, pse)
		self.assertEqual(plus_packet.payload, payload)
		self.assertEqual(plus_packet.pcf_type, pcf_type)
		self.assertEqual(plus_packet.pcf_value, pcf_value)
		self.assertEqual(plus_packet.pcf_integrity, pcf_integrity)
		self.assertEqual(plus_packet.is_valid(), True)


	def test_parse_packet_7(self):
		"""
		Tests parsing an extended packet.
		"""

		buf = bytes([
			0xD8, 0x00, 0x7F, 0xF1, # magic + flags (x bit set)
			0x12, 0x34, 0x56, 0x78, # cat
			0x12, 0x34, 0x56, 0x71, # cat..
			0x13, 0x11, 0x11, 0x12, # psn
			0x23, 0x22, 0x22, 0x23, # pse
			0x00, 0x00, 0xF3, # PCF Type := 0x00,
			# PCF Len 60, PCF I = 11b,
			0x01, 0x02, 0x03, 0x04,
			0x05, 0x06, # 6 bytes PCF value
			0x99, 0x98, 0x97, 0x96]) # 4 bytes payload

		# This needs to fail because pcf_len is 60 but pcf_value + payload
		# aren't even that long in the buf
		with self.assertRaises(ValueError):
			plus_packet = packet.parse_packet(buf)


class TestSerialize(unittest.TestCase):
	"""
	Serialization tests.
	"""

	def test_serialize_1(self):
		"""
		Tests serialization of a packet.
		"""

		buf = bytes([
			0xD8, 0x00, 0x7F, 0xFA, #magic + flags
			0x12, 0x34, 0x56, 0x78, #cat
			0x21, 0x43, 0x65, 0x87,
			0x87, 0x65, 0x43, 0x21, #psn
			0x11, 0x22, 0x33, 0x44, #pse
			0x01, 0x02, 0x03, 0x04, #payload
			0x10, 0x20, 0x30, 0x40, #payload
			0x99, 0x90, 0x99, 0x90])

		l = True
		r = False
		s = True

		cat = 0x1234567821436587
		psn = 0x87654321
		pse = 0x11223344

		payload = bytes([
			0x01, 0x02, 0x03, 0x04,
			0x10, 0x20, 0x30, 0x40,
			0x99, 0x90, 0x99, 0x90])

		plus_packet = packet.new_basic_packet(l, r, s, cat, psn, pse, payload)

		self.assertEqual(plus_packet.to_bytes(), buf)


	def test_serialize_2(self):
		"""
		Tests serialization of a packet.
		"""

		buf = bytes([
			0xD8, 0x00, 0x7F, 0xFF, # magic + flags (x bit set)
			0x12, 0x34, 0x56, 0x78, # cat
			0x12, 0x34, 0x56, 0x78, # cat..
			0x13, 0x11, 0x11, 0x11, # psn
			0x23, 0x22, 0x22, 0x22, # pse
			0x01, 0x1B, # PCF Type := 0x01,
			# PCF Len 6, PCF I = 11b,
			0x01, 0x02, 0x03, 0x04,
			0x05, 0x06, # 6 bytes PCF value
			0x99, 0x98, 0x97, 0x96]) # 4 bytes payload

		l = True
		r = True
		s = True
		cat = 0x1234567812345678
		psn = 0x13111111
		pse = 0x23222222
		pcf_type = 0x01
		pcf_len = 0x06
		pcf_integrity = 0x03
		pcf_value = bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06])
		payload = bytes([0x99, 0x98, 0x97, 0x96])

		plus_packet = packet.new_extended_packet(l, r, s, cat, psn, pse, pcf_type, pcf_integrity, pcf_value, payload)

		self.assertEqual(plus_packet.to_bytes(), buf)

	
	def test_serialize_3(self):
		"""
		Tests serialization of a packet.
		"""

		buf = bytes([
			0xD8, 0x00, 0x7F, 0xFF, # magic + flags (x bit set)
			0x12, 0x34, 0x56, 0x78, # cat
			0x12, 0x34, 0x56, 0x78, # cat..
			0x13, 0x11, 0x11, 0x11, # psn
			0x23, 0x22, 0x22, 0x22, # pse
			0x00, 0x01, 0x1B, # PCF Type := 0x0100,
			# PCF Len 6, PCF I = 11b,
			0x01, 0x02, 0x03, 0x04,
			0x05, 0x06, # 6 bytes PCF value
			0x99, 0x98, 0x97, 0x96]) # 4 bytes payload

		l = True
		r = True
		s = True
		cat = 0x1234567812345678
		psn = 0x13111111
		pse = 0x23222222
		pcf_type = 0x0100
		pcf_len = 0x06
		pcf_integrity = 0x03
		pcf_value = bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06])
		payload = bytes([0x99, 0x98, 0x97, 0x96])

		plus_packet = packet.new_extended_packet(l, r, s, cat, psn, pse, pcf_type, pcf_integrity, pcf_value, payload)

		self.assertEqual(plus_packet.to_bytes(), buf)


	def test_serialize_4(self):
		"""
		Tests serialization of a packet.
		"""

		buf = bytes([
			0xD8, 0x00, 0x7F, 0xFF, # magic + flags (x bit set)
			0x12, 0x34, 0x56, 0x78, # cat
			0x12, 0x34, 0x56, 0x78, # cat..
			0x13, 0x11, 0x11, 0x11, # psn
			0x23, 0x22, 0x22, 0x22, # pse
			0x00, 0x01, 0x00, # PCF Type := 0x0100,
			# PCF Len := 0, PCF I := 00b,
			0x01, 0x02, 0x03, 0x04,
			0x05, 0x06, # 
			0x99, 0x98, 0x97, 0x96]) # 10 bytes payload

		l = True
		r = True
		s = True
		cat = 0x1234567812345678
		psn = 0x13111111
		pse = 0x23222222
		pcf_type = 0x0100
		pcf_len = 0x00
		pcf_integrity = 0x00
		pcf_value = bytes([])
		payload = bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x99, 0x98, 0x97, 0x96])

		plus_packet = packet.new_extended_packet(l, r, s, cat, psn, pse, pcf_type, pcf_integrity, pcf_value, payload)

		self.assertEqual(plus_packet.to_bytes(), buf)


	def test_serialize_5(self):
		"""
		Tests serialization of a packet.
		"""

		buf = bytes([
			0xD8, 0x00, 0x7F, 0xFF, # magic + flags (x bit set)
			0x12, 0x34, 0x56, 0x78, # cat
			0x12, 0x34, 0x56, 0x78, # cat..
			0x13, 0x11, 0x11, 0x11, # psn
			0x23, 0x22, 0x22, 0x22, # pse
			0xFF, 0x01, 0x00, # PCF Type := 0xFF,
			# PCF Len := 0, PCF I := 00b,
			0x01, 0x02, 0x03, 0x04,
			0x05, 0x06, # 
			0x99, 0x98, 0x97, 0x96]) # 10 bytes payload

		l = True
		r = True
		s = True
		cat = 0x1234567812345678
		psn = 0x13111111
		pse = 0x23222222
		pcf_type = 0xFF
		pcf_len = None
		pcf_integrity = None
		pcf_value = None
		payload = bytes([0x01, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x99, 0x98, 0x97, 0x96])

		plus_packet = packet.new_extended_packet(l, r, s, cat, psn, pse, pcf_type, pcf_integrity, pcf_value, payload)

		self.assertEqual(plus_packet.to_bytes(), buf)


import random

class TestFuzzy(unittest.TestCase):
	"""
	Fuzzy testing. Let's hope this detects things we didn't think of.
	"""

	def _random_packet(self):
		"""
		Returns a random packet.
		"""

		n = random.randint(0,1)

		l = bool(random.randint(0,1))
		r = bool(random.randint(0,1))
		s = bool(random.randint(0,1))
		cat = random.randint(0, 2**64 -1)
		psn = random.randint(0, 2**32 -1)
		pse = random.randint(0, 2**32 -1)
		pcf_type = random.randint(0, 2**16 -1)
		pcf_value = self._random_buf_1()
		pcf_integrity = random.randint(0, 3)
		payload = self._random_buf_2()

		return packet.new_extended_packet(l, r, s, cat, psn, pse, pcf_type, pcf_integrity, pcf_value, payload)


	def test_fuzzy_3(self):
		"""
		Make random packets. Then unparse and parse again and compare.
		"""

		i = 0
		m = 0
		n = 0
		while i < 1024*100:
			plus_packet = None
			plus_packet_ = None

			try:
				plus_packet = self._random_packet()
				n += 1
				buf = plus_packet.to_bytes()
				plus_packet_ = packet.parse_packet(buf)
			except ValueError as e:
				pass

			if plus_packet_ == None:
				i += 1
				continue

			self.assertEqual(plus_packet.l, plus_packet_.l)
			self.assertEqual(plus_packet.r, plus_packet_.r)
			self.assertEqual(plus_packet.s, plus_packet_.s)
			self.assertEqual(plus_packet.x, plus_packet_.x)
			self.assertEqual(plus_packet.cat, plus_packet_.cat)
			self.assertEqual(plus_packet.psn, plus_packet_.psn)
			self.assertEqual(plus_packet.pse, plus_packet_.pse)
			self.assertEqual(plus_packet.payload, plus_packet_.payload)
			self.assertEqual(plus_packet.pcf_type, plus_packet_.pcf_type)
			self.assertEqual(plus_packet.pcf_value, plus_packet_.pcf_value)
			self.assertEqual(plus_packet.pcf_integrity, plus_packet_.pcf_integrity)
			self.assertEqual(plus_packet.is_valid(), True)
			self.assertEqual(plus_packet_.is_valid(), True)

			i += 1
			m += 1

		print(n, m)


	def _random_buf_1(self):
		"""
		Randomly alter a valid buffer (== can be parsed) and returns it.
		"""

		buf = ([
			0xD8, 0x00, 0x7F, 0xFF, # magic + flags (x bit set)
			0x12, 0x34, 0x56, 0x78, # cat
			0x12, 0x34, 0x56, 0x78, # cat..
			0x13, 0x11, 0x11, 0x11, # psn
			0x23, 0x22, 0x22, 0x22, # pse
			0x01, 0x1B, # PCF Type := 0x01,
			# PCF Len 6, PCF I = 11b,
			0x01, 0x02, 0x03, 0x04,
			0x05, 0x06, # 6 bytes PCF value
			0x99, 0x98, 0x97, 0x96])

		n = random.randint(1, 10)

		i = 0
		while i < n:
			j = random.randint(0, len(buf)-1)
			k = random.randint(0, 255)

			buf[j] = k

			i += 1

		return bytes(buf)


	def _random_buf_2(self):
		buf = [0xD8, 0x00, 0x7F, 0xFF]

		n = random.randint(1, 100)

		i = 0
		while i < n:
			k = random.randint(0, 255)
			buf.append(k)
			i += 1

		return bytes(buf)


	def test_fuzzy_1(self):
		"""
		Fuzzy testing.

		If parsing of a packet is successful, then unparsing must be
		successful as well and the buffers must match.
		"""

		i = 0

		while i < 1024*100:
			buf = self._random_buf_1()

			plus_packet = None

			try:
				plus_packet = packet.parse_packet(buf)
			except:
				plus_packet = None

			if plus_packet != None:
				try:
					self.assertEqual(plus_packet.to_bytes(), buf)
				except:
					print(plus_packet.to_dict())
					raise ValueError("Buffer mismatch?")

			i += 1

	def test_fuzzy_2(self):
		"""
		Fuzzy testing.

		If parsing of a packet is successful, then unparsing must be
		successful as well and the buffers must match.
		"""

		i = 0

		while i < 1024*100:
			buf = self._random_buf_2()

			plus_packet = None

			try:
				plus_packet = packet.parse_packet(buf)
			except:
				plus_packet = None

			if plus_packet != None:
				try:
					self.assertEqual(plus_packet.to_bytes(), buf)
				except:
					print(plus_packet.to_dict())
					raise ValueError("Buffer mismatch?")

			i += 1


if __name__ == "__main__":
	unittest.main()
