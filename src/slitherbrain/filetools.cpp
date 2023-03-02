#include "includes/slitherbrain.hpp"

namespace slitherbrain
{
    namespace filetools
    {
        string pathJoinTmp(string path)
        {
            string tmppath = filesystem::temp_directory_path();
            if (tmppath[tmppath.length() - 1] == FSLASH)
            {
                return tmppath + path;
            }

            return tmppath + FSLASH + path;
        }

        void writeStringToFile(string fpath, string contents)
        {
            fstream ofile;
            ofile.open(fpath);
            if (!ofile)
            {
                cout << "\033Error: \033: Failed to write to file, skipped..." << endl;
            }

            ofile << contents;
            ofile.close();
        }

        string processCodeAndSaveTemp(string code)
        {
            slitherbrain::strtools::trimChar(code, slitherbrain::consts::cTO_TRIM);
            string tmppath = slitherbrain::utils::randomString(10);
            string joined_path = pathJoinTmp(tmppath);
            int new_file = mkstemp64((char *)joined_path.c_str());
            writeStringToFile(joined_path, code);

            return joined_path;
        }
    }
}