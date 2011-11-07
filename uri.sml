structure Uri :> URI =
struct

    open ParserCombinators
    infixr 4 << >>
    infixr 3 &&
    infix  2 -- ##
    infix  2 wth suchthat return guard when
    infixr 1 || <|> ??
    open CharParser

    datatype host = IPVF of string * string (* possible future encodings *)
		  | IPV6 of int * int * int * int * int * int * int * int
		  | IPV4 of int * int * int * int | REGNAME of string
    datatype path = ABS of string list | REL of string list
    type auth = string option * host * int option
    type uri  = { scheme : string option, auth : auth option, path : path,
		  query : string option, fragment : string option }
    exception Uri of string

    (* helper definitions *)
    val delims    = String.explode ":/?#[]@"
    val subdelims = String.explode "!$&'()*+,;="
    fun dig d   = if Char.isDigit d then Char.ord d - Char.ord #"0"
		  else Char.ord (Char.toLower d) - Char.ord #"a" + 10
    fun optP p = p wth SOME <|> succeed NONE
    fun transnum b     = List.foldl (fn (s, d) => b * d + s) 0
    val decimal        = repeat1 digit wth transnum 10 o List.map dig
    val hexadecimal    = repeat1 hexDigit wth transnum 16 o List.map dig
    (* characters *)
    val penc    = char #"%" >> hexDigit && hexDigit
		       wth (fn (u, l) => Char.chr(16 * dig u + dig l))
    val unres   = alphaNum || oneOf (String.explode "-._~")
    val subd    = oneOf (String.explode "!$&'()*+,;=")
    val pchar   = penc <|> unres <|> subd <|> char #":" <|> char #"@"
    (* path segments *)
    val segNENC = repeat1 (penc <|> unres <|> subd <|> char #"@")
			  wth String.implode
    val segNE   = repeat1 pchar wth String.implode
    val seg     = repeat pchar wth String.implode
    val segsAb  = repeat (char #"/" >> seg)
    (* paths *)
    val pathAbE = segsAb wth ABS
    val pathRL  = segNE   && segsAb wth REL o op::
    val pathNS  = segNENC && segsAb wth REL o op::
    val pathAbs = char #"/" >> ((segNE && segsAb wth op::) <|> succeed [])
		       wth ABS
    (* authority constructs *)
    val regName = repeat (unres <|> penc <|> subd) wth String.implode
    val decOct  = decimal suchthat (fn x => x < 256)
    val ipv4    = decOct && char #"." >> decOct && char #"." >> decOct
			 && char #"." >> decOct
			 wth flat4
    val h16     = hexadecimal suchthat (fn x => x < 0x10000)
    val ls32    = (try (h16) && char #":" >> h16)
		      <|> ipv4
		      wth (fn (w, x, y, z) => (256 * w + x, 256 * y + z))
    val ipv6    =
	let
	    fun p0 x acc  = if x = 0 then acc else p0 (x - 1) (0 :: acc)
	    fun check xs  = case xs of
				[x1, x2, x3, x4, x5, x6, x7, x8] => 
				succeed (x1, x2, x3, x4, x5, x6, x7, x8)
			      | _ => fail "malformed ipv6 address"
	    fun pad xs ys = if length xs + length ys <= 8
			    then check (xs @ p0 (8 - length xs - length ys) ys)
			    else fail "malformed ipv6 address"
	in separate h16 (char #":") &&
		    optP (string "::" >> separate h16 (char #":")) && optP ipv4
		    -- (fn (xs, (oys, ot)) =>
			   case oys of
			       SOME ys =>
			       (case ot of
				    SOME (w, x, y, z) =>
				    pad xs (ys @ [256 * w + x, 256 * y + z])
				  | NONE => pad xs ys)
			     | NONE =>
			       (case ot of
				    SOME (w, x, y, z) =>
				    check (xs @ [256 * w + x, 256 * y + z])
				  | NONE => check xs))
	end
    val ipvF    = char #"v" >> (repeat1 hexDigit wth String.implode)
		       && char #"." >> (repeat1 (unres <|> subd <|> char #":")
						wth String.implode)
    val port    = decimal
    val uinfo   = repeat (penc || unres || subd || char #":") wth String.implode
    val host    = middle (char #"[") (ipvF wth IPVF <|> ipv6 wth IPV6)
			 (char #"]")
			 <|> ipv4 wth IPV4 <|> regName wth REGNAME
    val auth    = optP (try (uinfo << char #"@")) && host &&
		       optP (char #":" >> port) wth flat3
    (* scheme *)
    val schemeP   =
	letter && repeat (alphaNum <|> oneOf [#"+", #"-", #"."])
	       wth String.implode o List.map Char.toLower o op::
    (* query or fragment *)
    val queryFrag = repeat (pchar <|> char #"/" <|> char #"?")
			   wth String.implode
    (* hierarchical part *)
    val hierPart  = (try (string "//") >> (auth wth SOME) && pathAbE)
			<|> (pathAbs <|> pathRL <|>
				     succeed (REL [])) wth (fn x => (NONE, x))
    val relPart   = (try (string "//") >> (auth wth SOME) && pathAbE)
			<|> (pathAbs <|> pathNS <|> succeed (REL []))
			wth (fn x => (NONE, x))

    (* uri parsers *)
    val absUriNend : uri charParser =
	schemeP && char #":" >> hierPart && optP (char #"?" >> queryFrag)
		wth (fn (sch, ((oaut, pth), oqu)) =>
			{ scheme = SOME sch, auth = oaut, path = pth,
			  query = oqu, fragment = NONE })

    val absUri : uri charParser = absUriNend << eos

    val uri    : uri charParser =
	absUriNend && optP (char #"#" >> queryFrag) << eos
		    wth (fn (au, ofr) =>
			    { scheme = #scheme au, auth = #auth au,
			      path = #path au, query = #query au,
			      fragment = ofr})
    val relRef : uri charParser =
	relPart && optP (char #"?" >> queryFrag) &&
		optP (char #"#" >> queryFrag) << eos
		wth (fn ((oaut, pth), (oqu, ofr)) =>
			{ scheme = NONE, auth = oaut, path = pth,
			  query = oqu, fragment = ofr})

    val uriRef = uri || relRef

    fun maybe j n =
     fn SOME k => j k
      | NONE   => n
    fun flip  f (a, b) = f (b, a)
    fun curry f a b = f (a, b)
    fun cflip f = curry (flip f)

    (* Smart constructors for URIs and relative references. They sanitize
       the input, and so might fail. *)
    fun mkRec (u : {scheme : string option, auth : auth option, path : path,
		    query  : string option, fragment : string option}) =
	maybe
	    (Sum.sum (fn e => raise Uri ("Malformed scheme:\n" ^ e))
		     (fn _ => u) o parseString (schemeP << eos))
	    u
	    (#scheme u)
    fun mkUri scheme authO pth queryO fragO =
	mkRec {scheme = SOME scheme, auth = authO, path = pth,
	       query  = queryO, fragment = fragO}
    fun mkRel authO pth queryO fragO =
	mkRec {scheme = NONE, auth = authO, path = pth,
	       query  = queryO, fragment = fragO}

    (* Destructor for the URIs and relative references *)
    fun parts u = u

    (* URI pretty printing *)
    fun pctTrans extras =
	let fun tr c = if Char.isAlphaNum c orelse
			  List.exists (fn y => y = c) 
				      ([#"-", #".", #"_", #"~"] @ extras)
		       then str c
		       else "%"^ Int.fmt StringCvt.HEX (Char.ord c)
	in String.translate tr
	end

    fun pathToString p =
	let
	    val tr = pctTrans (#":" :: #"@" :: subdelims)
	    fun aux st xs = st ^ String.concatWith "/" (List.map tr xs)
	in case p
	    of ABS ss => aux "/" ss
	     | REL ss => aux ""  ss
	end

    fun hostToString h =
	let val iths     = Int.fmt StringCvt.HEX
	    val itds     = Int.fmt StringCvt.DEC
	in case h of
	       IPVF (prot, host) => "[v" ^ prot ^ "." ^ host ^ "]"
	     | IPV6 (h1, h2, h3, h4, h5, h6, h7, h8) =>
	       "[" ^ String.concatWith ":"
                       (map iths [h1, h2, h3, h4, h5, h6, h7, h8]) ^ "]"
	     | IPV4 (o1, o2, o3, o4) =>
	       itds o1 ^ "." ^ itds o2 ^ "." ^ itds o3 ^ "." ^ itds o4
	     | REGNAME s => pctTrans subdelims s
	end

    fun authToString (uinfo, h, pt) =
	maybe (cflip op^ "@" o pctTrans (#":" :: subdelims)) "" uinfo ^
	hostToString h ^
	maybe (curry op^ ":" o Int.toString) "" pt

    fun toString (u : uri) =
	let val tr = pctTrans (#"/" :: #"?" :: #":" :: #"@" :: subdelims)
	in
	    maybe (cflip op^ ":") "" (#scheme u) ^
	    maybe (curry op^ "//" o authToString) "" (#auth u) ^
	    pathToString (#path u) ^
	    maybe (curry op^ "?"  o tr) "" (#query u) ^
	    maybe (curry op^ "#"  o tr) "" (#fragment u)
	end

end

