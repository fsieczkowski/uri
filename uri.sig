signature URI =
(* URI parsing, printing and quoting library *)
sig

    datatype host = IPVF of string * string (* possible future encodings *)
		  | IPV6 of int * int * int * int * int * int * int * int
		  | IPV4 of int * int * int * int | REGNAME of string
    datatype path = ABS of string list | REL of string list
    type     auth = string option * host * int option
    type uri
    exception Uri of string

    (* Smart constructors for URIs and relative references. They sanitize
       the input, and so might fail. *)
    val mkUri  : string -> auth option -> path -> string option -> string option
		 -> uri
    val mkRel  : auth option -> path -> string option -> string option
		 -> uri
    val mkRec  : {scheme : string option, auth : auth option, path : path,
		  query  : string option, fragment : string option}
		 -> uri

    (* Parsers for URIs and relative references. *)
    (* This parser allows all well-formed, non-relative URIs *)
    val uri    : uri CharParser.charParser
    (* This parser allows only absolute URIs without fragments *)
    val absUri : uri CharParser.charParser
    (* This parser parses relative references *)
    val relRef : uri CharParser.charParser
    (* This parser parses any well-formed URI or relative reference *)
    val uriRef : uri CharParser.charParser

    (* Destructor for the URIs and relative references *)
    val parts : uri -> {scheme : string option, auth : auth option, path : path,
			query  : string option, fragment : string option}
    (* A formatter for URIs and relative references *)
    val toString : uri -> string

end
