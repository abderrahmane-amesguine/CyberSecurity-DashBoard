import React from 'react';
import { motion } from "framer-motion";

export default function PendingUserCard({ user, onApprove, onReject }) {
  return (
    <motion.div 
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      className="bg-white p-4 rounded-xl shadow-md flex flex-col gap-4 hover:shadow-lg transition-shadow"
    >
      <div className="flex justify-between items-center">
        <div>
          <h3 className="text-lg font-semibold">{user.email}</h3>
          <p className="text-sm text-gray-500">Requested to join</p>
        </div>
      </div>

      <div className="flex gap-3">
        <button
          onClick={() => onApprove(user.email)}
          className="bg-green-500 hover:bg-green-600 text-white px-4 py-2 rounded-lg transition-all"
        >
          Approve
        </button>
        <button
          onClick={() => onReject(user.email)}
          className="bg-red-500 hover:bg-red-600 text-white px-4 py-2 rounded-lg transition-all"
        >
          Reject
        </button>
      </div>
    </motion.div>
  );
}
