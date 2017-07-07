import unittest
import packet

class TestDummy(unittest.TestCase):

	def test_dummy(self):
		self.assertEqual(True, True)


class TestPacket(unittest.TestCase):

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



if __name__ == "__main__":
	unittest.main()
