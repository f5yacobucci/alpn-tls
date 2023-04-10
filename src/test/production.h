#define NUM_CERTS    5
#define TUPLE_ELEMS  2
#define MAX_ELEM_LEN 4096

#define CERT_ELEM 0
#define KEY_ELEM  1

/* Elem 0: Add certificate PEM, run fixup-pem-data.sh to replace newlines from file */
/* Elem 1: Add key PEM, run fixup-pem-data.sh to replace newlines from file */
static const char fake_certs[NUM_CERTS][TUPLE_ELEMS][MAX_ELEM_LEN] = {
  { "", "" },
  { "", "" },
  { "", "" },
  { "", "" },
  { "", "" },
};
