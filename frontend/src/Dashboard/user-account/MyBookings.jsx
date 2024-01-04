import { useFetchData } from "../../hooks/useFetchData";
import { BASE_URL } from "../../../config";
import DoctorCard from "../../components/Doctors/DoctorCard.jsx";
import { Loading } from "../../Loader/Loading.jsx";
import { Error } from "../../components/Error/Error.jsx";
export const MyBookings = () => {
  const {
    data: appointments,
    loading,
    error,
  } = useFetchData(`${BASE_URL}/users/appointments/my-appointments`);
  return (
    <div>
      {loading && !error && <Loading />}
      {error && !loading && <Error errMessage={error} />}
      {!loading && !error && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
          {appointments.map((doctor) => (
            <DoctorCard doctor={doctor} key={doctor._id} />
          ))}
        </div>
      )}
      {!loading && !error && appointments.length ===0 && <h2 className="mt-5 text-center yext-headingColor leading-7 text-[20px] font-semibold text-primaryColor">You did not book any appointments</h2>}
    </div>
  );
};
