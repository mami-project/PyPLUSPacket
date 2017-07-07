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


if __name__ == "__main__":
	unittest.main()
