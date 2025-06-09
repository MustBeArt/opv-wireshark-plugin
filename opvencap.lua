-- Opulent Voice encapsulated protocol dissector for Wireshark

local opvencap_protocol = Proto("opvencap", "Opulent Voice encapsulated protocol")

local sender_id = ProtoField.bytes("opvencap.sender_id", "Sender ID")
local auth_token = ProtoField.bytes("opvencap.auth_token", "Authentication Token")
local reserved = ProtoField.bytes("opvencap.reserved", "Reserved")

opvencap_protocol.fields = { sender_id, auth_token, reserved }

local base40 = {
    "!",
    "A", "B", "C", "D", "E", "F", "G", "H", "I", "J",
    "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T",
    "U", "V", "W", "X", "Y", "Z",
    "0", "1", "2", "3", "4", "5", "6", "7", "8", "9",
    "-", "/", "."
}
function decode_callsign(sender_id)
    local callsign = ""
    for i = 0, 9 do
        local remainder = sender_id % 40
        if remainder > 39 or remainder == 0 then
            callsign = "Invalid"
            return callsign
        end
        callsign = callsign .. base40[remainder+1]
        sender_id = (sender_id - remainder) / 40
        if sender_id == 0 then
            return callsign
        end
    end
end  

function opvencap_protocol.dissector(buffer, pinfo, tree)
   length = buffer:len()
    -- Check if the buffer is empty
    if length == 0 then return end

    sender = 0
    for i = 0, 5, 1 do
        sender = sender * 256
        sender = sender + buffer(i,1):uint()
    end

    -- Set the protocol name in the packet list
    pinfo.cols.protocol = opvencap_protocol.name

    -- Create a subtree for this protocol
    local subtree = tree:add(opvencap_protocol, buffer(), "Opulent Voice encapsulated protocol")
    subtree:add(sender_id, buffer(0, 6)):append_text(" (" .. decode_callsign(sender) .. ")")
    subtree:add(auth_token, buffer(6, 3)):append_text(" (Unverified)")
    subtree:add(reserved, buffer(9, 3))
end
-- Add the dissector to the UDP port 57372
local udp_port = DissectorTable.get("udp.port")
udp_port:add(57372, opvencap_protocol)
