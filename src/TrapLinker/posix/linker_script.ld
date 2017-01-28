PROVIDE_HIDDEN(_TRaP_text_begin = ADDR(.text));
PROVIDE_HIDDEN(_TRaP_text_end = ADDR(.text) + SIZEOF(.text));
/*PROVIDE_HIDDEN(_TRaP_trap_begin = ADDR(.txtrp));*/
/*PROVIDE_HIDDEN(_TRaP_trap_end = ADDR(.txtrp) + SIZEOF(.txtrp));*/
PROVIDE_HIDDEN(_TRaP_xptramp_begin = ADDR(.textramp));
PROVIDE_HIDDEN(_TRaP_xptramp_end = ADDR(.textramp) + SIZEOF(.textramp));
PROVIDE_HIDDEN(_TRaP_dynamic = ADDR(.dynamic));
