PROVIDE_HIDDEN(_TRaP_got_begin = ADDR(.got));
PROVIDE_HIDDEN(_TRaP_got_end = ADDR(.got) + SIZEOF(.got));
PROVIDE_HIDDEN(_TRaP_got_plt_begin = ADDR(.got.plt));
PROVIDE_HIDDEN(_TRaP_got_plt_end = ADDR(.got.plt) + SIZEOF(.got.plt));
