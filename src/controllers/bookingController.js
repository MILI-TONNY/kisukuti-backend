'use strict';

const db     = require('../config/database');
const logger = require('../utils/logger');

const SERVICE_PRICES = {
  wedding: 45000, birthday: 18000, meeting: 22000,
  dinner: 35000, traditional: 30000, custom: 25000,
};

async function createBooking(req, res) {
  const { name, email, phone, service, eventDate, guests, venue, notes } = req.body;
  const userId = req.user?.id || null;

  const booking = db.bookings.create({
    userId, name, email, phone, service,
    eventDate, guests, venue, notes,
    amount: SERVICE_PRICES[service] || 0,
  });

  db.audit.log('BOOKING_CREATED', userId || 'guest', { bookingId: booking.id, service, eventDate, ip: getIP(req) });
  logger.info(`Booking created: ${booking.bookingRef} — ${service} on ${eventDate}`);

  res.status(201).json({
    success: true,
    message: 'Booking created. Proceed to payment to confirm.',
    data: {
      id:         booking.id,
      bookingRef: booking.bookingRef,
      service:    booking.service,
      eventDate:  booking.eventDate,
      amount:     booking.amount,
      status:     booking.status,
      payUrl:     `/api/payments/initiate`,
    },
  });
}

async function getMyBookings(req, res) {
  const bookings = db.bookings.findByUser(req.user.id);
  res.json({ success: true, data: bookings, total: bookings.length });
}

async function getBooking(req, res) {
  const booking = db.bookings.findById(req.params.id);
  if (!booking) return res.status(404).json({ success: false, error: 'Booking not found.' });

  if (req.user.role !== 'admin' && booking.userId !== req.user.id) {
    return res.status(403).json({ success: false, error: 'Access denied.' });
  }
  res.json({ success: true, data: booking });
}

async function cancelBooking(req, res) {
  const booking = db.bookings.findById(req.params.id);
  if (!booking) return res.status(404).json({ success: false, error: 'Booking not found.' });
  if (req.user.role !== 'admin' && booking.userId !== req.user.id) {
    return res.status(403).json({ success: false, error: 'Access denied.' });
  }
  if (booking.status === 'confirmed') {
    return res.status(400).json({ success: false, error: 'Confirmed bookings cannot be cancelled online. Please contact support.' });
  }
  if (booking.status === 'cancelled') {
    return res.status(400).json({ success: false, error: 'Booking is already cancelled.' });
  }
  db.bookings.update(booking.id, { status: 'cancelled', cancelledAt: new Date().toISOString(), cancelReason: req.body.reason || 'Client cancelled' });
  db.audit.log('BOOKING_CANCELLED', req.user.id, { bookingId: booking.id, ip: getIP(req) });
  res.json({ success: true, message: 'Booking cancelled successfully.' });
}

async function getAllBookings(req, res) {
  const { status, service } = req.query;
  const bookings = db.bookings.findAll({ status, service });
  res.json({ success: true, data: bookings, total: bookings.length });
}

function getIP(req) {
  return req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket?.remoteAddress || 'unknown';
}

module.exports = { createBooking, getMyBookings, getBooking, cancelBooking, getAllBookings };
