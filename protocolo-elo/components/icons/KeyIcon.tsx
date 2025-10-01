import React from 'react';

const KeyIcon: React.FC<React.SVGProps<SVGSVGElement>> = (props) => (
  <svg
    {...props}
    xmlns="http://www.w3.org/2000/svg"
    width="24"
    height="24"
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    strokeWidth="2"
    strokeLinecap="round"
    strokeLinejoin="round"
  >
    <path d="m21.73 12.27-2.24-2.24a5.5 5.5 0 0 0-7.78 0l-2.24 2.24a5.5 5.5 0 0 0 0 7.78l2.24 2.24a5.5 5.5 0 0 0 7.78 0l2.24-2.24a5.5 5.5 0 0 0 0-7.78Z" />
    <path d="m15 5-3 3" />
    <path d="m9 11 4 4" />
  </svg>
);

export default KeyIcon;
