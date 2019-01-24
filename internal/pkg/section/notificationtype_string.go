// Code generated by "stringer -type=NotificationType"; DO NOT EDIT.

package section

import "strconv"

const (
	_NotificationType_name_0 = "NTHeartbeat"
	_NotificationType_name_1 = "NTCapHashNotKnownNTBadMessage"
	_NotificationType_name_2 = "NTRcvInconsistentMsgNTNoAssertionsExist"
	_NotificationType_name_3 = "NTMsgTooLarge"
	_NotificationType_name_4 = "NTUnspecServerErrNTServerNotCapable"
	_NotificationType_name_5 = "NTNoAssertionAvail"
)

var (
	_NotificationType_index_1 = [...]uint8{0, 17, 29}
	_NotificationType_index_2 = [...]uint8{0, 20, 39}
	_NotificationType_index_4 = [...]uint8{0, 17, 35}
)

func (i NotificationType) String() string {
	switch {
	case i == 100:
		return _NotificationType_name_0
	case 399 <= i && i <= 400:
		i -= 399
		return _NotificationType_name_1[_NotificationType_index_1[i]:_NotificationType_index_1[i+1]]
	case 403 <= i && i <= 404:
		i -= 403
		return _NotificationType_name_2[_NotificationType_index_2[i]:_NotificationType_index_2[i+1]]
	case i == 413:
		return _NotificationType_name_3
	case 500 <= i && i <= 501:
		i -= 500
		return _NotificationType_name_4[_NotificationType_index_4[i]:_NotificationType_index_4[i+1]]
	case i == 504:
		return _NotificationType_name_5
	default:
		return "NotificationType(" + strconv.FormatInt(int64(i), 10) + ")"
	}
}