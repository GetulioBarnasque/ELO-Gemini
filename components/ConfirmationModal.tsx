import React from 'react';

interface ConfirmationModalProps {
  isOpen: boolean;
  onClose: () => void;
  onConfirm: () => void;
  title: string;
  message: string;
}

const ConfirmationModal: React.FC<ConfirmationModalProps> = ({
  isOpen,
  onClose,
  onConfirm,
  title,
  message,
}) => {
  if (!isOpen) {
    return null;
  }

  return (
    <div className="fixed inset-0 bg-black bg-opacity-75 flex items-center justify-center z-50">
      <div className="bg-gray-800 rounded-lg shadow-xl w-full max-w-md p-6 mx-4">
        <h2 className="text-xl font-bold text-white mb-4">{title}</h2>
        <p className="text-gray-300 mb-6">{message}</p>
        <div className="flex justify-end gap-4">
          <button
            onClick={onClose}
            className="px-4 py-2 font-semibold text-gray-200 bg-gray-600 rounded-md hover:bg-gray-500 transition-colors"
          >
            Cancelar
          </button>
          <button
            onClick={onConfirm}
            className="px-4 py-2 font-bold text-white bg-red-600 rounded-md hover:bg-red-700 transition-colors"
          >
            Apagar
          </button>
        </div>
      </div>
    </div>
  );
};

export default ConfirmationModal;
