import { NAV } from "../components/Layout";
import { useLocation } from "react-router-dom";

export function Pending() {
  const { pathname } = useLocation();
  const item = NAV.find((n) => n.to === pathname);
  return (
    <div className="page">
      <h1>{item?.label}</h1>
      <div className="note">This screen is delivered in Phase {item?.phase}. Its data will come from the API like
        every other screen, with nothing hardcoded.</div>
    </div>
  );
}
