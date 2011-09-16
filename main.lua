-- encryption / verification ------------------------------------------------
local hmac; do
  local rep = string.rep
  local blocksize = 64
  local opad = rep('\92',blocksize)
  local ipad = rep('\54',blocksize)
  local h = md5.sum
  local hexh = md5.sumhexa
  local xor = md5.exor

  function hmac(message, key)
    if #key > blocksize then key = h(key) end
    if #key < blocksize then
      key = key .. string.rep('\0',blocksize-#key)
    end
    return hexh(xor(key,opad) .. h(xor(key,ipad)..message))
  end
end
-----------------------------------------------------------------------

-- local toolbox ------------------------------------------------------
local format = string.format
local gsub = string.gsub
-----------------------------------------------------------------------

-- request handler ----------------------------------------------------
function main(web, req)
  --Get the private token used for signing Textmarks requests.
  local textmarks_token = mongodb:query('keys',
    {textmarks_token = {["$exists"] = true}}):next()
  --If the query turned up nil (no token), then keep calm and carry on.
  --Otherwise, hoist that token.
  if textmarks_token then
    textmarks_token = textmarks_token.textmarks_token
  end

  --Gather the parameters of the request.
  local params = web:params()

  ------ Parameters ------

  -- The message recieved.
  local msg = params.msg or ""
  -- The requesting phone number. (Used in verification.)
  local tel = params.tel or "+16107610054"
  -- The TextMarks UID of the requesting user.
  local uid = params.uid or "1277842"
  -- The TextMarks action code:
  -- REQ for user messages to the TextMark,
  -- SUB or UNSUB for subscription management requests
  --   generated through the TextMarks system.
  local act = params.act or "REQ"
  -- The epoch time of the request (used in verification).
  local rqt = params.rqt
  -- The keyword the request was sent to (useful for hosting
  --   multiple TextMarks with one application).
  -- Also used in verification.
  local kwd = params.kwd
  -- The signature sent by TextMarks.
  local sig = params.sig

  --The calculated digest of the message
  --(requires all components to be present).
  local digest = kwd and tel and rqt and textmarks_token
    and hmac(kwd..tel..rqt,textmarks_token)

  --Whether the message was signed with the calculated signature.
  --If this value isn't true, the message should not be trusted
  --(don't allow any changes, but you can still respond).
  local signed = sig and sig == digest

  -------------------------

  do ---- logging ----
    local lmc = {}

    lmc.date = os.date "%c"
    lmc.rqt = rqt
    lmc.rct = os.time()
    lmc.tel = tel
    lmc.uid = uid
    lmc.act = act
    lmc.msg = msg
    lmc.kwd = kwd
    lmc.signed = signed
    -- Don't log valid signatures.
    if not signed then lmc.sig = sig
  end --- logging ----

  ------ Local toolbox ------

  -- Send the page response.
  local function respond(body)
    web:page(body,200,'OK')
  end

  ------ Action ------

  -- Subscription handling
  if act=="SUB" then
    respond""
  elseif act=="UNSUB" then
    respond""

  -- Request handling
  else
    respond"Watch this space (text MADAM to 41411 for the old crazy)."
  end
end
