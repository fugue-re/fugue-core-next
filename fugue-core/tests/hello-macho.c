#ifdef MACHO_RELOCATABLE
extern int external(int value);
#else
static int external(int value) {
    return value;
}
#endif

void *external_address = (void *)&external;

int fugue_entry(int value) {
    return external(value) + 1;
}

int main(void) {
    return fugue_entry(1);
}
