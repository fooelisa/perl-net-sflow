#!/usr/bin/perl
#
#
# My first perl project ;)
# Elisa Jasinska <elisa.jasinska@ams-ix.net>
#
# sFlow.pm - 2006/07/28
#
# Please send comments or bug reports to <sflow@ams-ix.net>
#
#
# sFlow v4 RFC 3176 
# http://www.ietf.org/rfc/rfc3176.txt
# Dataformat: http://jasinska.de/sFlow/sFlowV4FormatDiagram/
#
# sFlow v5 Memo
# http://sflow.org/sflow_version_5.txt
# Dataformat: http://jasinska.de/sFlow/sFlowV5FormatDiagram/
#
#
# Copyright (c) 2006 AMS-IX B.V.
#
# This package is free software and is provided "as is" without express 
# or implied warranty.  It may be used, redistributed and/or modified 
# under the terms of the Perl Artistic License (see
# http://www.perl.com/perl/misc/Artistic.html)
#


package Net::sFlow;


use strict;
use warnings;

require Exporter;

# convert ip notations
use Net::IP;

# decode the packet header data
use NetPacket::Ethernet;
use NetPacket::IP;
use NetPacket::IPv6;
use NetPacket::UDP;
use NetPacket::TCP;

# 64bit integers
use Math::BigInt;


our $VERSION = '0.03';
our @EXPORT_OK = qw(decode);


# constants

use constant SFLOWv4                        => 4;
use constant SFLOWv5                        => 5;

use constant UNKNOWNIPVERSION               => 0;
use constant IPv4                           => 1;
use constant IPv6                           => 2;

# sFlow v4 constants

use constant FLOWSAMPLE_SFLOWv4             => 1;
use constant COUNTERSAMPLE_SFLOWv4          => 2;

use constant HEADERDATA_SFLOWv4             => 1;
use constant IPv4DATA_SFLOWv4               => 2;
use constant IPv6DATA_SFLOWv4               => 3;

use constant SWITCHDATA_SFLOWv4             => 1;
use constant ROUTERDATA_SFLOWv4             => 2;
use constant GATEWAYDATA_SFLOWv4            => 3;
use constant USERDATA_SFLOWv4               => 4;
use constant URLDATA_SFLOWv4                => 5;

use constant GENERICCOUNTER_SFLOWv4         => 1;
use constant ETHERNETCOUNTER_SFLOWv4        => 2;
use constant TOKENRINGCOUNTER_SFLOWv4       => 3;
use constant FDDICOUNTER_SFLOWv4            => 4;
use constant VGCOUNTER_SFLOWv4              => 5;
use constant WANCOUNTER_SFLOWv4             => 6;
use constant VLANCOUNTER_SFLOWv4            => 7;

# sFlow v5 constants

use constant FLOWSAMPLE_SFLOWv5             => 1;
use constant COUNTERSAMPLE_SFLOWv5          => 2;
use constant EXPANDEDFLOWSAMPLE_SFLOWv5     => 3;
use constant EXPANDEDCOUNTERSAMPLE_SFLOWv5  => 4;

use constant HEADERDATA_SFLOWv5             => 1;
use constant ETHERNETFRAMEDATA_SFLOWv5      => 2;
use constant IPv4DATA_SFLOWv5               => 3;
use constant IPv6DATA_SFLOWv5               => 4;
use constant SWITCHDATA_SFLOWv5             => 1001;
use constant ROUTERDATA_SFLOWv5             => 1002;
use constant GATEWAYDATA_SFLOWv5            => 1003;
use constant USERDATA_SFLOWv5               => 1004;
use constant URLDATA_SFLOWv5                => 1005;
use constant MPLSDATA_SFLOWv5               => 1006;
use constant NATDATA_SFLOWv5                => 1007;
use constant MPLSTUNNEL_SFLOWv5             => 1008;
use constant MPLSVC_SFLOWv5                 => 1009;
use constant MPLSFEC_SFLOWv5                => 1010;
use constant MPLSLVPFEC_SFLOWv5             => 1011;
use constant VLANTUNNEL_SFLOWv5             => 1012;

use constant GENERICCOUNTER_SFLOWv5         => 1;
use constant ETHERNETCOUNTER_SFLOWv5        => 2;
use constant TOKENRINGCOUNTER_SFLOWv5       => 3;
use constant VGCOUNTER_SFLOWv5              => 4;
use constant VLANCOUNTER_SFLOWv5            => 5;
use constant PROCESSORCOUNTER_SFLOWv5       => 1001;




sub decode {

  my $sFlowDatagramPacked = shift;
  my %sFlowDatagram = ();
  my @sFlowSamples = ();
  my @errors = ();
  my $error = undef;
  my $subProcessed = undef;

  my $offset = 0;

  ($sFlowDatagram{sFlowVersion},
   $sFlowDatagram{AgentIpVersion}) = unpack("NN", $sFlowDatagramPacked);

  $offset += 8; 

  ($subProcessed, $error) = &_decodeIpAddress(\$offset, \$sFlowDatagramPacked, \%sFlowDatagram, undef, \@sFlowSamples, 
                                              $sFlowDatagram{AgentIpVersion}, "AgentIp", 1);

  unless ($subProcessed) {
    push @errors, $error; 
    %sFlowDatagram = ();
    return (\%sFlowDatagram, \@sFlowSamples, \@errors);
  }


####### sFlow V4 #######

  if ($sFlowDatagram{sFlowVersion} <= SFLOWv4) {

    (undef,
     $sFlowDatagram{datagramSequenceNumber},
     $sFlowDatagram{agentUptime},
     $sFlowDatagram{samplesInPacket}) = unpack("a$offset N3", $sFlowDatagramPacked);

    $offset += 12;

    # parse samples
    my $samplesCount = undef;
    for ($samplesCount = 0; $samplesCount < $sFlowDatagram{samplesInPacket}; $samplesCount++) {

      my %sFlowSample = ();
      push @sFlowSamples, \%sFlowSample;

      (undef, $sFlowSample{sampleType}) = unpack("a$offset N", $sFlowDatagramPacked);
      $offset += 4;


      # FLOWSAMPLE
      if ($sFlowSample{sampleType} == FLOWSAMPLE_SFLOWv4) {

        (undef, $sFlowSample{sampleSequenceNumber}) = unpack("a$offset N", $sFlowDatagramPacked);
        $offset += 4;

        my $sourceId = undef;

        (undef,
         $sourceId,
         $sFlowSample{samplingRate},
         $sFlowSample{samplePool},
         $sFlowSample{drops},
         $sFlowSample{inputInterface},
         $sFlowSample{outputInterface},
         $sFlowSample{packetDataType}) = unpack("a$offset N7", $sFlowDatagramPacked);

        $offset += 28;

        $sFlowSample{sourceIdType} = $sourceId >> 24;
        $sFlowSample{sourceIdIndex} = $sourceId & 2 ** 24 - 1;

        # packet data type: header
        if ($sFlowSample{packetDataType} == HEADERDATA_SFLOWv4) {
          ($subProcessed, $error) = &_decodeHeaderData(\$offset, \$sFlowDatagramPacked, \%sFlowDatagram, \%sFlowSample, \@sFlowSamples); 
          unless ($subProcessed) {
            push @errors, $error;
          }
        }

        # packet data type: IPv4
        elsif ($sFlowSample{packetDataType} == IPv4DATA_SFLOWv4) {
          &_decodeIPv4Data(\$offset, \$sFlowDatagramPacked, \%sFlowSample);
        }

        # packet data type: IPv6
        elsif ($sFlowSample{packetDataType} == IPv6DATA_SFLOWv4){
          &_decodeIPv6Data(\$offset, \$sFlowDatagramPacked, \%sFlowSample);
        }

        else { 
          $error = "ERROR: [sFlow.pm] <sFlowV4:PacketData> AgentIP: $sFlowDatagram{AgentIp}, Datagram: $sFlowDatagram{datagramSequenceNumber} - Unknown packet data type: $sFlowSample{packetDataType} - remained datagram skipped";
          push @errors, $error;
          pop @sFlowSamples; 
		      return (\%sFlowDatagram, \@sFlowSamples, \@errors); 
        }

        (undef, $sFlowSample{extendedDataInSample}) = unpack("a$offset N", $sFlowDatagramPacked);
        $offset += 4;

        my $extendedDataCount = undef;
        for ($extendedDataCount = 0; $extendedDataCount < $sFlowSample{extendedDataInSample}; $extendedDataCount++) {

          my $extendedDataType = undef;

          (undef, $extendedDataType) = unpack("a$offset N", $sFlowDatagramPacked);
          $offset += 4;

          # extended data: switch
          if ($extendedDataType == SWITCHDATA_SFLOWv4) {
            &_decodeSwitchData(\$offset, \$sFlowDatagramPacked, \%sFlowSample);
          }

          # extended data: router
          elsif ($extendedDataType == ROUTERDATA_SFLOWv4) {

            ($subProcessed, $error) = &_decodeRouterData(\$offset, \$sFlowDatagramPacked, \%sFlowDatagram, \%sFlowSample, \@sFlowSamples);

            unless ($subProcessed) {
              push @errors, $error;
              pop @sFlowSamples;
              return (\%sFlowDatagram, \@sFlowSamples, \@errors);
            }

          }

          # extended data: gateway
          elsif ($extendedDataType == GATEWAYDATA_SFLOWv4) {

            ($subProcessed, $error) = &_decodeGatewayData(\$offset, \$sFlowDatagramPacked, \%sFlowDatagram, \%sFlowSample, \@sFlowSamples);

            unless ($subProcessed) {
              push @errors, $error;
              pop @sFlowSamples;
              return (\%sFlowDatagram, \@sFlowSamples, \@errors);
            }
  
          }

          # extended data: user
          elsif ($extendedDataType == USERDATA_SFLOWv4) {
            &_decodeUserData(\$offset, \$sFlowDatagramPacked, \%sFlowDatagram, \%sFlowSample);
          }

          # extended data: url
          # added in v.3.
          elsif ($extendedDataType == URLDATA_SFLOWv4) {
            &_decodeUrlData(\$offset, \$sFlowDatagramPacked, \%sFlowDatagram, \%sFlowSample);
          }

          else { 
            $error = "ERROR: [sFlow.pm] <sFlowV4:ExtendedData> AgentIP: $sFlowDatagram{AgentIp}, Datagram: $sFlowDatagram{datagramSequenceNumber} - Unknown extended data type: $extendedDataType - remained datagram skipped";
            push @errors, $error;
            pop @sFlowSamples; 
		        return (\%sFlowDatagram, \@sFlowSamples, \@errors); 
          }

        }

      }

      # COUNTERSAMPLE
      elsif ($sFlowSample{sampleType} == COUNTERSAMPLE_SFLOWv4) {

        my $sourceId = undef;

        (undef,
         $sFlowSample{sampleSequenceNumber},
         $sourceId,
         $sFlowSample{counterSamplingInterval},
         $sFlowSample{countersVersion}) = unpack("a$offset N4", $sFlowDatagramPacked);

        $offset += 16;
      
        $sFlowSample{sourceIdType} = $sourceId >> 24;
        $sFlowSample{sourceIdIndex} = $sourceId & 2 ** 24 - 1;

        # counterstype: generic
        if ($sFlowSample{countersVersion} == GENERICCOUNTER_SFLOWv4) {
          &_decodeCounterGeneric(\$offset, \$sFlowDatagramPacked, \%sFlowSample);
        }

        # counterstype: ethernet
        elsif ($sFlowSample{countersVersion} == ETHERNETCOUNTER_SFLOWv4) {
          &_decodeCounterGeneric(\$offset, \$sFlowDatagramPacked, \%sFlowSample);
          &_decodeCounterEthernet(\$offset, \$sFlowDatagramPacked, \%sFlowSample);
        }

        # counterstype: tokenring
        elsif ($sFlowSample{countersVersion} == TOKENRINGCOUNTER_SFLOWv4) {
          &_decodeCounterGeneric(\$offset, \$sFlowDatagramPacked, \%sFlowSample);
          &_decodeCounterTokenring(\$offset, \$sFlowDatagramPacked, \%sFlowSample);
        }

        # counterstype: fddi
        elsif ($sFlowSample{countersVersion} == FDDICOUNTER_SFLOWv4) {
          &_decodeCounterGeneric(\$offset, \$sFlowDatagramPacked, \%sFlowSample);
        }

        # counterstype: vg
        elsif ($sFlowSample{countersVersion} == VGCOUNTER_SFLOWv4) {
          &_decodeCounterGeneric(\$offset, \$sFlowDatagramPacked, \%sFlowSample);
          &_decodeCounterVg(\$offset, \$sFlowDatagramPacked, \%sFlowSample);
        }

        # counterstype: wan
        elsif ($sFlowSample{countersVersion} == WANCOUNTER_SFLOWv4) {
          &_decodeCounterGeneric(\$offset, \$sFlowDatagramPacked, \%sFlowSample);
        }

        # counterstype: vlan
        elsif ($sFlowSample{countersVersion} == VLANCOUNTER_SFLOWv4) {
          &_decodeCounterVlan(\$offset, \$sFlowDatagramPacked, \%sFlowSample);
        }

        else { 
          $error = "ERROR: [sFlow.pm] <sFlowV4:CountersType> AgentIP: $sFlowDatagram{AgentIp}, Datagram: $sFlowDatagram{datagramSequenceNumber} - Unknown counters type: $sFlowSample{countersVersion} - remained datagram skipped";
          push @errors, $error;
          pop @sFlowSamples; 
		      return (\%sFlowDatagram, \@sFlowSamples, \@errors); 
        }

      }

      else { 
        $error = "ERROR: [sFlow.pm] <sFlowV4:SampleType> AgentIP: $sFlowDatagram{AgentIp}, Datagram: $sFlowDatagram{datagramSequenceNumber} - Unknown sample type: $sFlowSample{sampleType} - remained datgram skipped";
        push @errors, $error;
        pop @sFlowSamples; 
		    return (\%sFlowDatagram, \@sFlowSamples, \@errors); 
      }

    }  

  }
  

####### sFlow V5 #######

  elsif ($sFlowDatagram{sFlowVersion} >= SFLOWv5) { 

    # v5 also provides a sub agent id
    (undef, $sFlowDatagram{subAgentId}) = unpack("a$offset N", $sFlowDatagramPacked);
    $offset += 4;

    (undef,
     $sFlowDatagram{datagramSequenceNumber},
     $sFlowDatagram{agentUptime},
     $sFlowDatagram{samplesInPacket}) = unpack("a$offset N3", $sFlowDatagramPacked);

    $offset += 12;

    # parse samples
    my $samplesCount = undef;
    for ($samplesCount = 0; $samplesCount < $sFlowDatagram{samplesInPacket}; $samplesCount++) {

      my %sFlowSample = ();
      push @sFlowSamples, \%sFlowSample;

      my $sampleType = undef;

      (undef, $sampleType,$sFlowSample{sampleLength}) = unpack("a$offset NN", $sFlowDatagramPacked);

      $offset += 8;

      $sFlowSample{sampleTypeEnterprise} = $sampleType >> 12;
      $sFlowSample{sampleTypeFormat} = $sampleType & 2 ** 12 - 1;

      my $sourceId = undef;
      my $flowRecords = undef;
      my $counterRecords = undef;

      if ($sFlowSample{sampleTypeEnterprise} == 0 and $sFlowSample{sampleTypeFormat} == FLOWSAMPLE_SFLOWv5) {

        (undef,
         $sFlowSample{sampleSequenceNumber},
         $sourceId,
         $sFlowSample{samplingRate},
         $sFlowSample{samplePool},
         $sFlowSample{drops},
         $sFlowSample{inputInterface},
         $sFlowSample{outputInterface},
         $sFlowSample{flowRecordsCount}) = unpack("a$offset N8", $sFlowDatagramPacked);

        $offset += 32;

        $sFlowSample{sourceIdType} = $sourceId >> 24;
        $sFlowSample{sourceIdIndex} = $sourceId & 2 ** 24 - 1;  

        for ($flowRecords = 0; $flowRecords < $sFlowSample{flowRecordsCount}; $flowRecords++) {

          ($subProcessed, $error) = &_decodeFlowRecord(\$offset, \$sFlowDatagramPacked, \%sFlowDatagram, \%sFlowSample, \@sFlowSamples, \@errors);

          unless ($subProcessed) {
            push @errors, $error;
            pop @sFlowSamples;
            return (\%sFlowDatagram, \@sFlowSamples, \@errors); 
          }

        }

      } 

      elsif ($sFlowSample{sampleTypeEnterprise} == 0 and $sFlowSample{sampleTypeFormat} == COUNTERSAMPLE_SFLOWv5) {

        (undef,
         $sFlowSample{sampleSequenceNumber},
         $sourceId,
         $sFlowSample{counterRecordsCount}) = unpack("a$offset N3", $sFlowDatagramPacked);

        $offset += 12;

        $sFlowSample{sourceIdType} = $sourceId >> 24;
        $sFlowSample{sourceIdIndex} = $sourceId & 2 ** 24 - 1;

        for ($counterRecords = 0; $counterRecords < $sFlowSample{counterRecordsCount}; $counterRecords++) {

          ($subProcessed, $error) = &_decodeCounterRecord(\$offset, \$sFlowDatagramPacked, \%sFlowDatagram, \%sFlowSample, \@sFlowSamples);

          unless ($subProcessed) {
            push @errors, $error;
            pop @sFlowSamples;
            return (\%sFlowDatagram, \@sFlowSamples, \@errors);
          }

        }

      } 

      elsif ($sFlowSample{sampleTypeEnterprise} == 0 and $sFlowSample{sampleTypeFormat} == EXPANDEDFLOWSAMPLE_SFLOWv5) {
      
        (undef,
         $sFlowSample{sampleSequenceNumber},
         $sFlowSample{sourceIdType},
         $sFlowSample{sourceIdIndex},
         $sFlowSample{samplingRate},
         $sFlowSample{samplePool},
         $sFlowSample{drops},
         $sFlowSample{inputInterfaceFormat},
         $sFlowSample{inputInterfaceValue},
         $sFlowSample{outputInterfaceFormat},
         $sFlowSample{outputInterfaceValue},
         $sFlowSample{flowRecordsCount}) = unpack("a$offset N11", $sFlowDatagramPacked);

        $offset += 44;

        for ($flowRecords = 0; $flowRecords < $sFlowSample{flowRecordsCount}; $flowRecords++) {

          ($subProcessed, $error) = &_decodeFlowRecord(\$offset, \$sFlowDatagramPacked, \%sFlowDatagram, \%sFlowSample, \@sFlowSamples, \@errors);

          unless ($subProcessed) {
            push @errors, $error;
            pop @sFlowSamples;
            return (\%sFlowDatagram, \@sFlowSamples, \@errors);
          }

        } 

      } 

      elsif ($sFlowSample{sampleTypeEnterprise} == 0 and $sFlowSample{sampleTypeFormat} == EXPANDEDCOUNTERSAMPLE_SFLOWv5) {

        (undef,
         $sFlowSample{sampleSequenceNumber},
         $sFlowSample{sourceIdType},
         $sFlowSample{sourceIdIndex},
         $sFlowSample{counterRecordsCount}) = unpack("a$offset N4", $sFlowDatagramPacked);

        $offset += 16;
  
        for ($counterRecords = 0; $counterRecords < $sFlowSample{counterRecordsCount}; $counterRecords++) {

          ($subProcessed, $error) = &_decodeCounterRecord(\$offset, \$sFlowDatagramPacked, \%sFlowDatagram, \%sFlowSample, \@sFlowSamples); 

          unless ($subProcessed) {
            push @errors, $error;
            pop @sFlowSamples;
            return (\%sFlowDatagram, \@sFlowSamples, \@errors);
          }

        }

      } 

      else { 
        $error = "ERROR: [sFlow.pm] <sFlowV5:SampleData> AgentIP: $sFlowDatagram{AgentIp} Datagram: $sFlowDatagram{datagramSequenceNumber} - Unknown sample enterprise: $sFlowSample{sampleTypeEnterprise} or format: $sFlowSample{sampleTypeFormat} - remained datagram skipped";
        push @errors, $error;
        pop @sFlowSamples; 
		    return (\%sFlowDatagram, \@sFlowSamples, \@errors); 
      }

    }

  }

  else { 
    $error = "ERROR: [sFlow.pm] AgentIP: $sFlowDatagram{AgentIp}, Datagram: $sFlowDatagram{datagramSequenceNumber} - Unknown sFlow Version: $sFlowDatagram{sFlowVersion}";
    push @errors, $error;
    %sFlowDatagram = ();
		return (\%sFlowDatagram, \@sFlowSamples, \@errors); 
  }
  
#  $error = "INFO: [sFlow.pm] AgentIP: $sFlowDatagram{AgentIp}, Datagram: $sFlowDatagram{datagramSequenceNumber} - Datagram processed";
#  push @errors, $error;
  return (\%sFlowDatagram, \@sFlowSamples, \@errors);

}

#################### END sub decode() #######################

sub _decodeIpAddress {

  my $offsetref = shift;
  my $sFlowDatagramPacked = shift;
  my $sFlowDatagram = shift;
  my $sFlowSample = shift;
  my $sFlowSamples = shift;
  my $IpVersion = shift;
  my $keyName = shift;
  my $DatagramOrSampleData = shift;

  my $error = undef;
  my $offset = $$offsetref;

  if (defined($DatagramOrSampleData)) {
    if ($IpVersion == IPv4) {  
      (undef, $sFlowDatagram->{$keyName}) = unpack("a$offset B32", $$sFlowDatagramPacked);
      $sFlowDatagram->{$keyName} = Net::IP::ip_bintoip($sFlowDatagram->{$keyName},4);
      $offset += 4;
    }

    elsif ($IpVersion == IPv6) { 
      (undef, $sFlowDatagram->{$keyName}) = unpack("a$offset B128", $$sFlowDatagramPacked);
      $sFlowDatagram->{$keyName} = Net::IP::ip_bintoip($sFlowDatagram->{$keyName},6);
      $offset += 16;
    }
  }

  else {
    if ($IpVersion == IPv4) {
      ($sFlowSample->{$keyName}) = unpack("a$offset B32", $$sFlowDatagramPacked);
      $sFlowSample->{$keyName} = Net::IP::ip_bintoip($sFlowSample->{$keyName},4);
      $offset += 4;
    }

    elsif ($IpVersion == IPv6) {
      ($sFlowSample->{$keyName}) = unpack("a$offset B128", $$sFlowDatagramPacked);
      $sFlowSample->{$keyName} = Net::IP::ip_bintoip($sFlowSample->{$keyName},6);
      $offset += 16;
    }
  }

  if ($IpVersion != IPv4 and $IpVersion != IPv6) {

    if (defined($DatagramOrSampleData)) { 

      # unknown ip version added in v5 
      if ($IpVersion == UNKNOWNIPVERSION) {
        $error = "ERROR: [sFlow.pm] AgentIP: Unknown agent ip version: $IpVersion - remained datagram skipped";
        return (undef, $error);
      }

      else {
        $error = "ERROR: [sFlow.pm] AgentIP: Unknown agent ip version: $IpVersion - remained datgram skipped";
        return (undef, $error);
      }

    }

    else { 
    
      # unknown ip version added in v5 
      if ($IpVersion == UNKNOWNIPVERSION) {
        $error = "ERROR: [sFlow.pm] AgentIP: $sFlowDatagram->{AgentIp}, Datagram: $sFlowDatagram->{datagramSequenceNumber}, Sample: $sFlowSample->{sampleSequenceNumber} - Unknown ip version: $IpVersion - remained datagram skipped";
        return (undef, $error);
      }
    
      else {
        $error = "ERROR: [sFlow.pm] AgentIP: $sFlowDatagram->{AgentIp}, Datagram: $sFlowDatagram->{datagramSequenceNumber}, Sample: $sFlowSample->{sampleSequenceNumber} - Unknown ip version: $IpVersion - remained datgram skipped";
        return (undef, $error);
      }      

    }

  }

  $$offsetref = $offset;
  return (1, undef);
}


sub _decodeFlowRecord {

  my $offsetref = shift;
  my $sFlowDatagramPacked = shift;
  my $sFlowDatagram = shift;
  my $sFlowSample = shift;
  my $sFlowSamples = shift;
  my $errors = shift;
  
  my $offset = $$offsetref;
  my $flowType = undef;
  my $flowDataLength = undef;
  my $error = undef;
  my $subProcessed = undef;
  
  (undef,
   $flowType,
   $flowDataLength) = unpack("a$offset NN", $$sFlowDatagramPacked);
  
  $offset += 8;
  
  my $flowTypeEnterprise = $flowType >> 12;
  my $flowTypeFormat = $flowType & 2 ** 12 - 1;

  if ($flowTypeEnterprise == 0) {
  
    if ($flowTypeFormat == HEADERDATA_SFLOWv5) {

      ($subProcessed, $error) = &_decodeHeaderData(\$offset, $sFlowDatagramPacked, $sFlowDatagram, $sFlowSample, $sFlowSamples);

      unless ($subProcessed) {
        push @{$errors}, $error;
      }

    } 

    elsif ($flowTypeFormat == SWITCHDATA_SFLOWv5) {
      &_decodeSwitchData(\$offset, $sFlowDatagramPacked, $sFlowSample);
    } 

    elsif ($flowTypeFormat == ETHERNETFRAMEDATA_SFLOWv5) {
      &_decodeEthernetFrameData(\$offset, $sFlowDatagramPacked, $sFlowSample);
    } 

    elsif ($flowTypeFormat == IPv4DATA_SFLOWv5) {
      &_decodeIPv4Data(\$offset, $sFlowDatagramPacked, $sFlowSample);
    } 

    elsif ($flowTypeFormat == IPv6DATA_SFLOWv5) {
      &_decodeIPv6Data(\$offset, $sFlowDatagramPacked, $sFlowSample);
    } 
  
    elsif ($flowTypeFormat == ROUTERDATA_SFLOWv5) {
      ($subProcessed, $error) = &_decodeRouterData(\$offset, $sFlowDatagramPacked, $sFlowDatagram, $sFlowSample, $sFlowSamples);

      unless ($subProcessed) {
        return (undef, $error);
      }

    } 

    elsif ($flowTypeFormat == GATEWAYDATA_SFLOWv5) {
      ($subProcessed, $error) = &_decodeGatewayData(\$offset, $sFlowDatagramPacked, $sFlowDatagram, $sFlowSample, $sFlowSamples);

      unless ($subProcessed) {
        return (undef, $error);
      }

    } 

    elsif ($flowTypeFormat == USERDATA_SFLOWv5) {
      &_decodeUserData(\$offset, $sFlowDatagramPacked, $sFlowDatagram, $sFlowSample);
    }   

    elsif ($flowTypeFormat == URLDATA_SFLOWv5) {
      &_decodeUrlData(\$offset, $sFlowDatagramPacked, $sFlowDatagram, $sFlowSample);
    } 

    elsif ($flowTypeFormat == MPLSDATA_SFLOWv5) {
      ($subProcessed, $error) = &_decodeMplsData(\$offset, $sFlowDatagramPacked, $sFlowDatagram, $sFlowSample, $sFlowSamples);

      unless ($subProcessed) {
        return (undef, $error);
      }

    } 

    elsif ($flowTypeFormat == NATDATA_SFLOWv5) {
      ($subProcessed, $error) = &_decodeNatData(\$offset, $sFlowDatagramPacked, $sFlowDatagram, $sFlowSample, $sFlowSamples);

      unless ($subProcessed) {
        return (undef, $error);
      }
    
    } 

    elsif ($flowTypeFormat == MPLSTUNNEL_SFLOWv5) {
      &_decodeMplsTunnel(\$offset, $sFlowDatagramPacked, $sFlowSample);
    } 

    elsif ($flowTypeFormat == MPLSVC_SFLOWv5) {
      &_decodeMplsVc(\$offset, $sFlowDatagramPacked, $sFlowSample);
    }  

    elsif ($flowTypeFormat == MPLSFEC_SFLOWv5) {
      &_decodeMplsFec(\$offset, $sFlowDatagramPacked, $sFlowSample);
    } 

    elsif ($flowTypeFormat == MPLSLVPFEC_SFLOWv5) {
      &_decodeMplsLpvFec(\$offset, $sFlowDatagramPacked, $sFlowSample);
    } 

    elsif ($flowTypeFormat == VLANTUNNEL_SFLOWv5) {
      &_decodeVlanTunnel(\$offset, $sFlowDatagramPacked, $sFlowSample);
    }
  
    else { 
      $error = "ERROR: [sFlow.pm] <sFlowV5:FlowData> AgentIP: $sFlowDatagram->{AgentIp}, Datagram: $sFlowDatagram->{datagramSequenceNumber}, Sample: $sFlowSample->{sampleSequenceNumber} - Unknown Flowdata format: $flowTypeFormat - remained datagram skipped";
		  return (undef, $error); 
    }
  
  }

  else { 
    $error = "ERROR: [sFlow.pm] <sFlowV5:FlowData> AgentIP: $sFlowDatagram->{AgentIp}, Datagram: $sFlowDatagram->{datagramSequenceNumber} - Unknown Flowdata enterprise: $flowTypeEnterprise - remained datagram skipped";
		return (undef, $error); 
  }

  $$offsetref = $offset;
  return (1,undef);
}


sub _decodeCounterRecord {

  my $offsetref = shift;
  my $sFlowDatagramPacked = shift;
  my $sFlowDatagram = shift;
  my $sFlowSample = shift;
  my $sFlowSamples = shift;

  my $offset = $$offsetref;
  my $counterType = undef;
  my $counterDataLength = undef;
  my $error = undef;

  (undef,
   $counterType,
   $sFlowSample->{counterDataLength}) = unpack("a$offset NN", $$sFlowDatagramPacked);

  $offset += 8;

  my $counterTypeEnterprise = $counterType >> 12;
  my $counterTypeFormat = $counterType & 2 ** 12 - 1;

  if ($counterTypeEnterprise == 0) {

    if ($counterTypeFormat == GENERICCOUNTER_SFLOWv5) {
      &_decodeCounterGeneric(\$offset, $sFlowDatagramPacked, $sFlowSample);
    }  

    elsif ($counterTypeFormat == ETHERNETCOUNTER_SFLOWv5) {
      &_decodeCounterEthernet(\$offset, $sFlowDatagramPacked, $sFlowSample);
    } 

    elsif ($counterTypeFormat == TOKENRINGCOUNTER_SFLOWv5) {
      &_decodeCounterTokenring(\$offset, $sFlowDatagramPacked, $sFlowSample);
    } 

    elsif ($counterTypeFormat == VGCOUNTER_SFLOWv5) {
      &_decodeCounterVg(\$offset, $sFlowDatagramPacked, $sFlowSample);
    } 

    elsif ($counterTypeFormat == VLANCOUNTER_SFLOWv5) {
      &_decodeCounterVlan(\$offset, $sFlowDatagramPacked, $sFlowSample);
    } 

    elsif ($counterTypeFormat == PROCESSORCOUNTER_SFLOWv5) {
      &_decodeCounterProcessor(\$offset, $sFlowDatagramPacked, $sFlowSample);
    }
   
    else { 
      $error = "ERROR: [sFlow.pm] <sFlowV5:CounterData> AgentIP: $sFlowDatagram->{AgentIp}, Datagram: $sFlowDatagram->{datagramSequenceNumber} - Unknown counterdata format: $counterTypeFormat - remained datgram skipped";
		  return (undef, $error); 
    }

  } 

  else { 
    $error = "ERROR: [sFlow.pm] <sFlowV5:CounterData> AgentIP: $sFlowDatagram->{AgentIp}, Datagram: $sFlowDatagram->{datagramSequenceNumber} - Unknown counterdata enterprise: $counterTypeEnterprise - remained datagram skipped";
	  return (undef, $error); 
  }
  
  $$offsetref = $offset;
  return (1, undef);
}


sub _decodeHeaderData {

  my $offsetref = shift;
  my $sFlowDatagramPacked = shift;
  my $sFlowDatagram = shift;
  my $sFlowSample = shift;
  my $sFlowSamples = shift;

  my $offset = $$offsetref;

  $sFlowSample->{HEADERDATA} = "HEADERDATA";

  (undef,
   $sFlowSample->{HeaderProtocol},
   $sFlowSample->{HeaderFrameLength}) = unpack("a$offset NN", $$sFlowDatagramPacked);

  $offset += 8;
  
  if ($sFlowDatagram->{sFlowVersion} == SFLOWv5) {
    (undef, $sFlowSample->{HeaderStrippedLength}) = unpack("a$offset N", $$sFlowDatagramPacked);
    $offset += 4;
  }

  (undef, $sFlowSample->{HeaderSizeByte}) = unpack("a$offset N", $$sFlowDatagramPacked);
  $offset += 4;

  # header size in bit
  $sFlowSample->{HeaderSizeBit} = $sFlowSample->{HeaderSizeByte} * 8;

  my $header = undef;
  $header = substr ($$sFlowDatagramPacked, $offset, $sFlowSample->{HeaderSizeByte});

  # we have to cut off a $sFlowSample->{HeaderSizeByte} mod 4 == 0 number of bytes 
  my $tmp = 4 - ($sFlowSample->{HeaderSizeByte} % 4);
  $tmp == 4 and $tmp = 0;

  $offset += ($sFlowSample->{HeaderSizeByte} + $tmp);

  # unpack ethernet header
  my $ethObj = NetPacket::Ethernet->decode($header);

  $sFlowSample->{HeaderEtherSrcMac} = $ethObj->{src_mac};
  $sFlowSample->{HeaderEtherDestMac} = $ethObj->{dest_mac};

  # unpack ip header
  my $ipObj = NetPacket::IPv6->decode($ethObj->{data});

  $sFlowSample->{HeaderVer} = $ipObj->{ver};
  $sFlowSample->{HeaderDatalen} = $ipObj->{datalen};

  $sFlowSample->{HeaderNexth} = $ipObj->{nexth};
  $sFlowSample->{HeaderProto} = $ipObj->{proto};

  $sFlowSample->{HeaderSrcIP} = $ipObj->{src_ip};
  $sFlowSample->{HeaderDestIP} = $ipObj->{dest_ip};

  # unpack udp or tcp header
  my $transportObj = undef;

  if ((exists($ipObj->{proto}) and $ipObj->{proto} == 6) or (exists($ipObj->{nexth}) and $ipObj->{nexth} == 6)) {
    $transportObj = NetPacket::TCP->decode($ipObj->{data});
    $sFlowSample->{HeaderTCPSrcPort} = $transportObj->{src_port};
    $sFlowSample->{HeaderTCPDestPort} = $transportObj->{dest_port};
  }
  
  elsif ((exists($ipObj->{proto}) and $ipObj->{proto} == 17) or (exists($ipObj->{nexth}) and $ipObj->{nexth} == 17)) {
    $transportObj = NetPacket::UDP->decode($ipObj->{data});
    $sFlowSample->{HeaderUDPSrcPort} = $transportObj->{src_port};
    $sFlowSample->{HeaderUDPDestPort} = $transportObj->{dest_port};
  }

  elsif ((exists($ipObj->{proto}) and $ipObj->{proto} == 1) or (exists($ipObj->{nexth}) and $ipObj->{nexth} == 1)) {
    my $icmpObj = NetPacket::ICMP->decode($ipObj->{data});
    $sFlowSample->{HeaderICMP} = 1;
  }

  elsif ((exists($ipObj->{proto}) and $ipObj->{proto} == 59) or (exists($ipObj->{nexth}) and $ipObj->{nexth} == 59)) {
    $sFlowSample->{NoTransportLayer} = 1;
  }

  elsif ((exists($ipObj->{proto}) and $ipObj->{proto} == 0) or (exists($ipObj->{nexth}) and $ipObj->{nexth} == 0)) {
    $sFlowSample->{NoTransportLayer} = 1;
  }
  
  else {
   
    my $proto = undef;
  
    if (exists($ipObj->{proto})) {
      $proto = $ipObj->{proto};
    } 
  
    elsif (exists($ipObj->{nexth})) {
      $proto = $ipObj->{nexth};
    }
  
    my $error = "WARN: [sFlow.pm] <HeaderDtata> AgentIP: $sFlowDatagram->{AgentIp}, Datagram: $sFlowDatagram->{datagramSequenceNumber}, Sample: $sFlowSample->{sampleSequenceNumber} - Unknown next header protocol: $proto - remained header skipped";
    return (undef, $error);
  } 

  $$offsetref = $offset;
  return (1, undef);
  
}


sub _decodeEthernetFrameData {

  my $offsetref = shift;
  my $sFlowDatagramPacked = shift;
  my $sFlowSample = shift;

  my $offset = $$offsetref;
  my $EtherSrcMac1 = undef;
  my $EtherSrcMac2 = undef;
  my $EtherDestMac1 = undef;
  my $EtherDestMac2 = undef;
   
  $sFlowSample->{ETHERNETFRAMEDATA} = "ETHERNETFRAMEDATA";
  
  (undef,
   $sFlowSample->{EtherMacPacketlength},
   $EtherSrcMac1,
   $EtherSrcMac2,
   $EtherDestMac1,
   $EtherDestMac2,
   $sFlowSample->{EtherPackettype}) = unpack("a$offset N6", $$sFlowDatagramPacked);
  
  $sFlowSample->{EtherSrcMac} = sprintf("%08x%04x", $EtherSrcMac1, $EtherSrcMac2);
  $sFlowSample->{EtherDestMac} = sprintf("%08x%04x", $EtherDestMac1, $EtherDestMac2);
 
  $offset += 24;
  $$offsetref = $offset;
}


sub _decodeIPv4Data {
  
  my $offsetref = shift;
  my $sFlowDatagramPacked = shift;
  my $sFlowSample = shift;
  
  my $offset = $$offsetref;
  
  $sFlowSample->{IPv4DATA} = "IPv4DATA";
  
  (undef,
   $sFlowSample->{IPv4Packetlength},
   $sFlowSample->{IPv4NextHeaderProtocol},
   $sFlowSample->{IPv4srcIp},
   $sFlowSample->{IPv4destIp},
   $sFlowSample->{IPv4srcPort},
   $sFlowSample->{IPv4destPort},
   $sFlowSample->{IPv4tcpFlags},
   $sFlowSample->{IPv4tos}) = unpack("a$offset N2B32B32N4", $$sFlowDatagramPacked); 
  
  $sFlowSample->{IPv4srcIp} = Net::IP::ip_bintoip($sFlowSample->{IPv4srcIp},4);
  $sFlowSample->{IPv4destIp} = Net::IP::ip_bintoip($sFlowSample->{IPv4destIp},4);
  
  $offset += 32;
  $$offsetref = $offset;
}


sub _decodeIPv6Data {
  
  my $offsetref = shift;
  my $sFlowDatagramPacked = shift;
  my $sFlowSample = shift;
  
  my $offset = $$offsetref;
  
  $sFlowSample->{IPv6DATA} = "IPv6DATA";

  (undef,
   $sFlowSample->{IPv6Packetlength},
   $sFlowSample->{IPv6NextHeaderProto},
   $sFlowSample->{IPv6srcIp},
   $sFlowSample->{IPv6destIp},
   $sFlowSample->{IPv6srcPort},
   $sFlowSample->{IPv6destPort},
   $sFlowSample->{IPv6tcpFlags},
   $sFlowSample->{IPv6Priority}) = unpack("a$offset N2B128B128N4", $$sFlowDatagramPacked);

  $sFlowSample->{IPv6srcIp} = Net::IP::ip_bintoip($sFlowSample->{IPv6srcIp},6);
  $sFlowSample->{IPv6destIp} = Net::IP::ip_bintoip($sFlowSample->{IPv6destIp},6);
   
  $offset += 56;
  $$offsetref = $offset;
}


sub _decodeSwitchData {

  my $offsetref = shift;
  my $sFlowDatagramPacked = shift;
  my $sFlowSample = shift;

  my $offset = $$offsetref;

  $sFlowSample->{SWITCHDATA} = "SWITCHDATA";

  (undef,
   $sFlowSample->{SwitchSrcVlan},
   $sFlowSample->{SwitchSrcPriority},
   $sFlowSample->{SwitchDestVlan},
   $sFlowSample->{SwitchDestPriority}) = unpack("a$offset N4", $$sFlowDatagramPacked);
  
  $offset += 16;
  $$offsetref = $offset;
}


sub _decodeRouterData {

  my $offsetref = shift;
  my $sFlowDatagramPacked = shift;
  my $sFlowDatagram = shift;
  my $sFlowSample = shift;
  my $sFlowSamples = shift;

  my $offset = $$offsetref;
  my $subProcessed = undef;
  my $error = undef;

  $sFlowSample->{ROUTERDATA} = "ROUTERDATA";

  (undef, $sFlowSample->{RouterIpVersionNextHopRouter}) = unpack("a$offset N", $$sFlowDatagramPacked);
  $offset += 4;

  ($subProcessed, $error) = &_decodeIpAddress(\$offset, $sFlowDatagramPacked, $sFlowDatagram, $sFlowSample, $sFlowSamples, 
                                              $sFlowSample->{RouterIpVersionNextHopRouter}, "RouterIpAddressNextHopRouter", undef);
  
  unless ($subProcessed) {
    return (undef, $error);
  }
  
  (undef, $sFlowSample->{RouterSrcMask},$sFlowSample->{RouterDestMask}) = unpack("a$offset NN", $$sFlowDatagramPacked);
  $offset += 8;

  $$offsetref = $offset;
  return (1, undef);
}


sub _decodeGatewayData {

  my $offsetref = shift;
  my $sFlowDatagramPacked = shift;
  my $sFlowDatagram = shift;
  my $sFlowSample = shift;
  my $sFlowSamples = shift;

  my $offset = $$offsetref;
  my $subProcessed = undef;
  my $error = undef;

  $sFlowSample->{GATEWAYDATA} = "GATEWAYDATA";

  if ($sFlowDatagram->{sFlowVersion} == SFLOWv5) {

    (undef, $sFlowSample->{GatewayIpVersionNextHopRouter}) = unpack("a$offset N", $$sFlowDatagramPacked);
    $offset += 4;

    ($subProcessed, $error) = &_decodeIpAddress(\$offset, $sFlowDatagramPacked, $sFlowDatagram, $sFlowSample, $sFlowSamples,
                                                $sFlowSample->{GatewayIpVersionNextHopRouter}, "GatewayIpVersionNextHopRouter", undef);

    unless ($subProcessed) {
      return (undef, $error);
    } 
  }

  (undef,
   $sFlowSample->{GatewayAsRouter},
   $sFlowSample->{GatewayAsSource},
   $sFlowSample->{GatewayAsSourcePeer},
   $sFlowSample->{GatewayDestAsPathsCount}) = unpack("a$offset N4", $$sFlowDatagramPacked);    

  $offset += 16;

  # array containing the single paths
  my @sFlowAsPaths = ();

  # reference to this array in extended data
  $sFlowSample->{GatewayDestAsPaths} = \@sFlowAsPaths;

  my $destAsPathCount = undef;
  for ($destAsPathCount = 0; $destAsPathCount < $sFlowSample->{GatewayDestAsPathsCount}; $destAsPathCount++) {

    # single path hash
    my %sFlowAsPath = ();

    # reference to this single path hash in the paths array
    push @sFlowAsPaths, \%sFlowAsPath; 
    
    (undef,
     $sFlowAsPath{asPathSegmentType},
     $sFlowAsPath{lengthAsList}) = unpack("a$offset NN", $$sFlowDatagramPacked);
    
    $offset += 8;

    # array containing the as numbers of a path
    my @sFlowAsNumber = ();

    # referece to this array in path hash
    $sFlowAsPath{AsPath} = \@sFlowAsNumber;

    my $asListLength = undef;
    for ($asListLength = 0; $asListLength < $sFlowAsPath{lengthAsList}; $asListLength++) {
      (undef, my $asNumber) = unpack("a$offset N", $$sFlowDatagramPacked);
      # push as number to array
      push @sFlowAsNumber, $asNumber;
      $offset += 4;
    }

  }
  # communities added in v.4.
  if ($sFlowDatagram->{sFlowVersion} == SFLOWv4) {

    (undef, $sFlowSample->{GatewayLengthCommunitiesList}) = unpack("a$offset N", $$sFlowDatagramPacked);

    $offset += 4;

    my @sFlowCommunities = ();
    $sFlowSample->{GatewayCommunities} = \@sFlowCommunities;

    my $commLength = undef;
    for ($commLength=0; $commLength < $sFlowSample->{GatewayLengthCommunitiesList}; $commLength++) {
      (undef, my $community) = unpack("a$offset N", $$sFlowDatagramPacked);
      push @sFlowCommunities, $community;
      $offset += 4;
    }
  }

  (undef, $sFlowSample->{localPref}) = unpack("a$offset N", $$sFlowDatagramPacked);
  $offset += 4;

  $$offsetref = $offset;
  return (1, undef);
}


sub _decodeUserData {

  my $offsetref = shift;
  my $sFlowDatagramPacked = shift;
  my $sFlowDatagram = shift;
  my $sFlowSample = shift;

  my $offset = $$offsetref;  

  $sFlowSample->{USERDATA} = "USERDATA";

  if ($sFlowDatagram->{sFlowVersion} == SFLOWv5) {
    (undef, $sFlowSample->{UserSrcCharset}) = unpack("a$offset N", $$sFlowDatagramPacked);
    $offset += 4;
  }

  # xxx - string length "A" ????
  (undef, $sFlowSample->{UserLengthSrcString}) = unpack("a$offset N", $$sFlowDatagramPacked);
  $offset += 4;

  (undef, $sFlowSample->{UserSrcString}) = unpack("a$offset A$sFlowSample->{UserLengthSrcString}", $$sFlowDatagramPacked);
  $offset += $sFlowSample->{UserLengthSrcString};

  if ($sFlowDatagram->{sFlowVersion} == SFLOWv5) {
    (undef, $sFlowSample->{UserDestCharset}) = unpack("a$offset N", $$sFlowDatagramPacked);
    $offset += 4;
  }

  (undef, $sFlowSample->{UserLengthDestString}) = unpack("a$offset N", $$sFlowDatagramPacked);
  $offset += 4;

  (undef, $sFlowSample->{UserDestString}) = unpack("a$offset A$sFlowSample->{UserLengthDestString}", $$sFlowDatagramPacked);
  $offset += $sFlowSample->{UserLengthDestString};
  
  $$offsetref = $offset;
}


sub _decodeUrlData {

  my $offsetref = shift;
  my $sFlowDatagramPacked = shift;
  my $sFlowDatagram = shift;
  my $sFlowSample = shift;

  my $offset = $$offsetref;
  
  $sFlowSample->{URLDATA} = "URLDATA";

  # xxx - string length "A" ????
  (undef, $sFlowSample->{UrlDirection}, $sFlowSample->{UrlLength}) = unpack("a$offset NN", $$sFlowDatagramPacked);
  $offset += 8;

  (undef, $sFlowSample->{Url}) = unpack("a$offset A$sFlowSample->{UrlLength}", $$sFlowDatagramPacked);
  $offset += $sFlowSample->{UrlLength};

  if ($sFlowDatagram->{sFlowVersion} == SFLOWv5) {

    (undef, $sFlowSample->{UrlHostLength}) = unpack("a$offset N", $$sFlowDatagramPacked);
    $offset += 4;

    (undef, $sFlowSample->{UrlHost}) = unpack("a$offset A$sFlowSample->{UrlHostLength}", $$sFlowDatagramPacked);
    $offset += $sFlowSample->{UrlHostLength};
  }
  
  $$offsetref = $offset;
}


sub _decodeMplsData {

  my $offsetref = shift;
  my $sFlowDatagramPacked = shift;
  my $sFlowDatagram = shift;
  my $sFlowSample = shift;
  my $sFlowSamples = shift;

  my $offset = $$offsetref;
  my $subProcessed = undef;
  my $error = undef;
 
  $sFlowSample->{MPLSDATA} = "MPLSDATA";
 
  (undef, $sFlowSample->{MplsIpVersionNextHopRouter}) = unpack("a$offset N", $$sFlowDatagramPacked);
  $offset += 4;
 
  ($subProcessed, $error) = &_decodeIpAddress(\$offset, $sFlowDatagramPacked, $sFlowDatagram, $sFlowSample, $sFlowSamples,
                                              $sFlowSample->{MplsIpVersionNextHopRouter}, "MplsIpVersionNextHopRouter", undef);

  unless ($subProcessed) {
    return (undef, $error); 
  }
 
  (undef, $sFlowSample->{MplsInLabesStackCount}) = unpack("a$offset N", $$sFlowDatagramPacked); 
  $offset += 4;
  
  my @MplsInLabelStack = ();
  $sFlowSample->{MplsInLabelStack} = \@MplsInLabelStack;
  my $MplsInLabelStackCount = undef;
  
  for ($MplsInLabelStackCount = 0; $MplsInLabelStackCount < $sFlowSample->{MplsInLabesStackCount}; $MplsInLabelStackCount++) {
    (undef, my $MplsInLabel) = unpack("a$offset N", $$sFlowDatagramPacked);
    push @MplsInLabelStack, $MplsInLabel;
    $offset += 4;
  }
  
  (undef, $sFlowSample->{MplsOutLabelStackCount}) = unpack("a$offset N", $$sFlowDatagramPacked); 
  $offset += 4;
  
  my @MplsOutLabelStack = ();
  $sFlowSample->{MplsOutLabelStack} = \@MplsInLabelStack;
  my $MplsOutLabelStackCount = undef;  

  for ($MplsOutLabelStackCount = 0; $MplsOutLabelStackCount < $sFlowSample->{MplsOutLabesStackCount}; $MplsOutLabelStackCount++) {
    (undef, my $MplsOutLabel) = unpack("a$offset N", $$sFlowDatagramPacked);
    push @MplsOutLabelStack, $MplsOutLabel;
    $offset += 4;
  }

  $$offsetref = $offset;
  return (1, undef);
}


sub _decodeNatData {
  
  my $offsetref = shift;
  my $sFlowDatagramPacked = shift;
  my $sFlowDatagram = shift;
  my $sFlowSample = shift;
  my $sFlowSamples = shift;

  my $offset = $$offsetref;
  my $subProcessed = undef;
  my $error = undef;

  $sFlowSample->{NATDATA} = "NATDATA";

  (undef, $sFlowSample->{NatIpVersionSrcAddress}) = unpack("a$offset N", $$sFlowDatagramPacked);
  $offset += 4;

  ($subProcessed, $error) = &_decodeIpAddress(\$offset, $sFlowDatagramPacked, $sFlowDatagram, $sFlowSample, $sFlowSamples,
                                              $sFlowSample->{NatIpVersionSrcAddress}, "NatIpVersionSrcAddress", undef);

  unless ($subProcessed) {
    return (undef, $error); 
  }
 
  (undef, $sFlowSample->{NatIpVersionDestAddress}) = unpack("a$offset N", $$sFlowDatagramPacked);
  $offset += 4;
 
  ($subProcessed, $error) = &_decodeIpAddress(\$offset, $sFlowDatagramPacked, $sFlowDatagram, $sFlowSample, $sFlowSamples,
                                              $sFlowSample->{NatIpVersionDestAddress}, "NatIpVersionDestAddress", undef);

  unless ($subProcessed) {
    return (undef, $error); 
  }

  $$offsetref = $offset;
  return (1, undef);
}


sub _decodeMplsTunnel {

  my $offsetref = shift;
  my $sFlowDatagramPacked = shift;
  my $sFlowSample = shift;

  my $offset = $$offsetref;
  
  $sFlowSample->{MPLSTUNNEL} = "MPLSTUNNEL";

  (undef, $sFlowSample->{MplsTunnelLength}) = unpack("a$offset N", $$sFlowDatagramPacked);
  $offset += 4;
  
  (undef, $sFlowSample->{MplsTunnelName}) = unpack("a$offset A$sFlowSample->{MplsTunnelLength}", $$sFlowDatagramPacked);
  $offset += $sFlowSample->{MplsTunnelLength};
  
  (undef, $sFlowSample->{MplsTunnelId},$sFlowSample->{MplsTunnelCosValue}) = unpack("a$offset NN", $$sFlowDatagramPacked);
  $offset += 8;
  
  $$offsetref = $offset;
}


sub _decodeMplsVc {

  my $offsetref = shift;
  my $sFlowDatagramPacked = shift;
  my $sFlowSample = shift;

  my $offset = $$offsetref;

  $sFlowSample->{MPLSVC} = "MPLSVC";

  (undef, $sFlowSample->{MplsVcInstanceNameLength}) = unpack("a$offset N", $$sFlowDatagramPacked);
  $offset += 4;
  
  (undef, $sFlowSample->{MplsVcInstanceName}) = unpack("a$offset A$sFlowSample->{MplsVcInstanceNameLength}", $$sFlowDatagramPacked);
  $offset += $sFlowSample->{MplsVcInstanceNameLength};
  
  (undef, $sFlowSample->{MplsVcId},$sFlowSample->{MplsVcLabelCosValue}) = unpack("a$offset NN", $$sFlowDatagramPacked);
  $offset += 8;
  
  $$offsetref = $offset;
}


sub _decodeMplsFec {

  my $offsetref = shift;
  my $sFlowDatagramPacked = shift;
  my $sFlowSample = shift;

  my $offset = $$offsetref;

  $sFlowSample->{MPLSFEC} = "MPLSFEC";

  (undef, $sFlowSample->{MplsFtnDescrLength}) = unpack("a$offset N", $$sFlowDatagramPacked);
  $offset += 4;
  
  (undef, $sFlowSample->{MplsFtnDescr}) = unpack("a$offset A$sFlowSample->{MplsFtnDescrLength}", $$sFlowDatagramPacked);
  $offset += $sFlowSample->{MplsFtrDescrLength};
  
  (undef, $sFlowSample->{MplsFtnMask}) = unpack("a$offset N", $$sFlowDatagramPacked);
  $offset += 4;
  
  $$offsetref = $offset;
}


sub _decodeMplsLpvFec {

  my $offsetref = shift;
  my $sFlowDatagramPacked = shift;
  my $sFlowSample = shift;

  my $offset = $$offsetref;
  
  $sFlowSample->{MPLSLPVFEC} = "MPLSLPVFEC";

  (undef, $sFlowSample->{MplsFecAddrPrefixLength}) = unpack("a$offset N", $$sFlowDatagramPacked);
  $offset += 4;

  $$offsetref = $offset;
}


sub _decodeVlanTunnel {

  my $offsetref = shift;
  my $sFlowDatagramPacked = shift;
  my $sFlowSample = shift;

  $sFlowSample->{VLANTUNNEL} = "VLANTUNNEL";

  my $offset = $$offsetref;

  (undef, $sFlowSample->{VlanTunnelLayerStackCount}) = unpack("a$offset N", $$sFlowDatagramPacked);
  $offset += 4;
  
  my @VlanTunnelLayerStack = ();
  $sFlowSample->{VlanTunnelLayerStack} = \@VlanTunnelLayerStack;
  my $VlanTunnelLayerCount = undef;

  for ($VlanTunnelLayerCount = 0; $VlanTunnelLayerCount < $sFlowSample->{VlanTunnelLayerStackCount}; $VlanTunnelLayerCount++) {
    (undef, my $VlanTunnelLayer) = unpack("a$offset N", $$sFlowDatagramPacked);
    push @VlanTunnelLayerStack, $VlanTunnelLayer;
    $offset += 4;
  }
  $$offsetref = $offset;
}


sub _decodeCounterGeneric {

  my $offsetref = shift;
  my $sFlowDatagramPacked = shift;
  my $sFlowSample = shift;

  $sFlowSample->{COUNTERGENERIC} = "COUNTERGENERIC";

  my $offset = $$offsetref;
  my $ifSpeed1 = undef; 
  my $ifSpeed2 = undef; 
  my $ifInOctets1 = undef;
  my $ifInOctets2 = undef;
  my $ifOutOctets1 = undef;
  my $ifOutOctets2 = undef;

  (undef,
   $sFlowSample->{ifIndex},
   $sFlowSample->{ifType},
   $ifSpeed1,
   $ifSpeed2,
   $sFlowSample->{ifDirection},
   $sFlowSample->{ifAdminStatus},
   $sFlowSample->{ifOperStatus},
   undef,
   $ifInOctets1,
   $ifInOctets2,
   $sFlowSample->{ifInUcastPkts},
   $sFlowSample->{ifInMulticastPkts},
   $sFlowSample->{ifInBroadcastPkts},
   $sFlowSample->{idInDiscards},
   $sFlowSample->{ifInErrors},
   $sFlowSample->{ifInUnknownProtos},
   $ifOutOctets1,
   $ifOutOctets2,
   $sFlowSample->{ifOutUcastPkts},
   $sFlowSample->{ifOutMulticastPkts},
   $sFlowSample->{ifOutBroadcastPkts},
   $sFlowSample->{ifOutDiscards},
   $sFlowSample->{ifOutErrors},
   $sFlowSample->{ifPromiscuousMode}) = unpack("a$offset N5B1B1B30N16", $$sFlowDatagramPacked);

  $offset += 88;

  $sFlowSample->{ifSpeed} = Math::BigInt->new("$ifSpeed1");
  $sFlowSample->{ifSpeed} = $sFlowSample->{ifSpeed} << 32;
  $sFlowSample->{ifSpeed} += $ifSpeed2;
 
  $sFlowSample->{idInOctets} = Math::BigInt->new("$ifInOctets1");
  $sFlowSample->{idInOctets} = $sFlowSample->{idInOctets} << 32;
  $sFlowSample->{idInOctets} += $ifInOctets2;

  $sFlowSample->{ifOutOctets} = Math::BigInt->new("$ifOutOctets1");
  $sFlowSample->{ifOutOctets} = $sFlowSample->{ifOutOctets} << 32;
  $sFlowSample->{ifOutOctets} += $ifOutOctets2;
  
  $$offsetref = $offset;
}


sub _decodeCounterEthernet {
  
  my $offsetref = shift;
  my $sFlowDatagramPacked = shift;
  my $sFlowSample = shift;

  my $offset = $$offsetref;

  $sFlowSample->{COUNTERETHERNET} = "COUNTERETHERNET";

  (undef,
   $sFlowSample->{dot3StatsAlignmentErrors},
   $sFlowSample->{dot3StatsFCSErrors},
   $sFlowSample->{dot3StatsSingleCollisionFrames},
   $sFlowSample->{dot3StatsMultipleCollisionFrames},
   $sFlowSample->{dot3StatsSQETestErrors},
   $sFlowSample->{dot3StatsDeferredTransmissions},
   $sFlowSample->{dot3StatsLateCollisions},
   $sFlowSample->{dot3StatsExcessiveCollisions},
   $sFlowSample->{dot3StatsInternalMacTransmitErrors},
   $sFlowSample->{dot3StatsCarrierSenseErrors},
   $sFlowSample->{dot3StatsFrameTooLongs},
   $sFlowSample->{dot3StatsInternalMacReceiveErrors},
   $sFlowSample->{dot3StatsSymbolErrors}) = unpack("a$offset N13", $$sFlowDatagramPacked);

  $offset += 52;
  $$offsetref = $offset;
} 


sub _decodeCounterTokenring {

  my $offsetref = shift;
  my $sFlowDatagramPacked = shift;
  my $sFlowSample = shift;

  my $offset = $$offsetref;

  $sFlowSample->{COUNTERTOKENRING} = "COUNTERTOKENRING";

  (undef,
   $sFlowSample->{dot5StatsLineErrors},
   $sFlowSample->{dot5StatsBurstErrors},
   $sFlowSample->{dot5StatsACErrors},
   $sFlowSample->{dot5StatsAbortTransErrors},
   $sFlowSample->{dot5StatsInternalErrors},
   $sFlowSample->{dot5StatsLostFrameErrors},
   $sFlowSample->{dot5StatsReceiveCongestions},
   $sFlowSample->{dot5StatsFrameCopiedErrors},
   $sFlowSample->{dot5StatsTokenErrors},
   $sFlowSample->{dot5StatsSoftErrors},
   $sFlowSample->{dot5StatsHardErrors},
   $sFlowSample->{dot5StatsSignalLoss},
   $sFlowSample->{dot5StatsTransmitBeacons},
   $sFlowSample->{dot5StatsRecoverys},
   $sFlowSample->{dot5StatsLobeWires},
   $sFlowSample->{dot5StatsRemoves},
   $sFlowSample->{dot5StatsSingles},
   $sFlowSample->{dot5StatsFreqErrors}) = unpack("a$offset N18", $$sFlowDatagramPacked);

  $offset += 72;
  $$offsetref = $offset;
}


sub _decodeCounterVg {

  my $offsetref = shift;
  my $sFlowDatagramPacked = shift;
  my $sFlowSample = shift;

  my $offset = $$offsetref;

  $sFlowSample->{COUNTERVG} = "COUNTERVG";

  my $dot12InHighPriorityOctets1 = undef;
  my $dot12InHighPriorityOctets2 = undef;
  my $dot12InNormPriorityOctets1 = undef;
  my $dot12InNormPriorityOctets2 = undef;
  my $dot12OutHighPriorityOctets1 = undef;
  my $dot12OutHighPriorityOctets2 = undef;
  my $dot12HCInHighPriorityOctets1 = undef;
  my $dot12HCInHighPriorityOctets2 = undef;
  my $dot12HCInNormPriorityOctets1 = undef;
  my $dot12HCInNormPriorityOctets2 = undef;
  my $dot12HCOutHighPriorityOctets1 = undef;
  my $dot12HCOutHighPriorityOctets2 = undef;

  (undef,
   $sFlowSample->{dot12InHighPriorityFrames},
   $dot12InHighPriorityOctets1,
   $dot12InHighPriorityOctets2,
   $sFlowSample->{dot12InNormPriorityFrames},
   $dot12InNormPriorityOctets1,
   $dot12InNormPriorityOctets2,
   $sFlowSample->{dot12InIPMErrors},
   $sFlowSample->{dot12InOversizeFrameErrors},
   $sFlowSample->{dot12InDataErrors},
   $sFlowSample->{dot12InNullAddressedFrames},
   $sFlowSample->{dot12OutHighPriorityFrames},
   $dot12OutHighPriorityOctets1,
   $dot12OutHighPriorityOctets2,
   $sFlowSample->{dot12TransitionIntoTrainings},
   $dot12HCInHighPriorityOctets1,
   $dot12HCInHighPriorityOctets2,
   $dot12HCInNormPriorityOctets1,
   $dot12HCInNormPriorityOctets2,
   $dot12HCOutHighPriorityOctets1,
   $dot12HCOutHighPriorityOctets2) = unpack("a$offset N20", $$sFlowDatagramPacked);

  $offset += 80;

  $sFlowSample->{dot12InHighPriorityOctets} = Math::BigInt->new("$dot12InHighPriorityOctets1");
  $sFlowSample->{dot12InHighPriorityOctets} = $sFlowSample->{dot12InHighPriorityOctets} << 32;
  $sFlowSample->{dot12InHighPriorityOctets} += $dot12InHighPriorityOctets2;

  $sFlowSample->{dot12InNormPriorityOctets} = Math::BigInt->new("$dot12InNormPriorityOctets1");
  $sFlowSample->{dot12InNormPriorityOctets} = $sFlowSample->{dot12InNormPriorityOctets} << 32;
  $sFlowSample->{dot12InNormPriorityOctets} += $dot12InNormPriorityOctets2;

  $sFlowSample->{dot12OutHighPriorityOctets} = Math::BigInt->new("$dot12OutHighPriorityOctets1");
  $sFlowSample->{dot12OutHighPriorityOctets} = $sFlowSample->{dot12OutHighPriorityOctets} << 32;
  $sFlowSample->{dot12OutHighPriorityOctets} += $dot12OutHighPriorityOctets2;

  $sFlowSample->{dot12HCInHighPriorityOctets} = Math::BigInt->new("$dot12HCInHighPriorityOctets1");
  $sFlowSample->{dot12HCInHighPriorityOctets} = $sFlowSample->{dot12HCInHighPriorityOctets} << 32;
  $sFlowSample->{dot12HCInHighPriorityOctets} += $dot12HCInHighPriorityOctets2;

  $sFlowSample->{dot12HCInNormPriorityOctets} = Math::BigInt->new("$dot12HCInNormPriorityOctets1");
  $sFlowSample->{dot12HCInNormPriorityOctets} = $sFlowSample->{dot12HCInNormPriorityOctets} << 32;
  $sFlowSample->{dot12HCInNormPriorityOctets} += $dot12HCInNormPriorityOctets2;

  $sFlowSample->{dot12HCOutHighPriorityOctets} = Math::BigInt->new("$dot12HCOutHighPriorityOctets1");
  $sFlowSample->{dot12HCOutHighPriorityOctets} = $sFlowSample->{dot12HCOutHighPriorityOctets} << 32;
  $sFlowSample->{dot12HCOutHighPriorityOctets} += $dot12HCOutHighPriorityOctets2;
  
  $$offsetref = $offset;
}


sub _decodeCounterVlan {

  my $offsetref = shift;
  my $sFlowDatagramPacked = shift;
  my $sFlowSample = shift;

  my $offset = $$offsetref;
  my $octets1 = undef;
  my $octets2 = undef;

  $sFlowSample->{COUNTERVLAN} = "COUNTERVLAN";

  (undef,
   $sFlowSample->{vlan_id},
   $octets1,
   $octets2,
   $sFlowSample->{ucastPkts},
   $sFlowSample->{multicastPkts},
   $sFlowSample->{broadcastPkts},
   $sFlowSample->{discards}) = unpack("a$offset N7", $$sFlowDatagramPacked);
  
  $offset += 28;

  $sFlowSample->{octets} = Math::BigInt->new("$octets1");
  $sFlowSample->{octets} = $sFlowSample->{octets} << 32;
  $sFlowSample->{octets} += $octets2;
   
  $$offsetref = $offset;
}


sub _decodeCounterProcessor {

  my $offsetref = shift;
  my $sFlowDatagramPacked = shift;
  my $sFlowSample = shift;
  
  my $offset = $$offsetref;
  my $memoryTotal1 = undef;
  my $memoryTotal2 = undef;
  my $memoryFree1 = undef;
  my $memoryFree2 = undef;

  $sFlowSample->{COUNTERPROCESSOR} = "COUNTERPROCESSOR";

  (undef,
   $sFlowSample->{cpu5s},
   $sFlowSample->{cpu1m},
   $sFlowSample->{cpu5m},
   $memoryTotal1,
   $memoryTotal2,
   $memoryFree1,
   $memoryFree2) = unpack("a$offset N7", $$sFlowDatagramPacked);

  $offset += 28;  

  $sFlowSample->{memoryTotal} = Math::BigInt->new("$memoryTotal1");
  $sFlowSample->{memoryTotal} = $sFlowSample->{memoryTotal} << 32;
  $sFlowSample->{memoryTotal} += $memoryTotal2;
  
  $sFlowSample->{memoryFree} = Math::BigInt->new("$memoryFree1");
  $sFlowSample->{memoryFree} = $sFlowSample->{memoryFree} << 32;
  $sFlowSample->{memoryFree} += $memoryFree2;

  $$offsetref = $offset;
} 

1;

__END__

=head1 NAME

Net::sFlow - decode sFlow datagrams.



=head1 SYNOPSIS

  use Net::sFlow;
  
  # decode udp payload (if needed)
  my $ethObj = NetPacket::Ethernet->decode($packet);
  my $ipObj = NetPacket::IPv6->decode($ethObj->{data});
  my $udpObj = NetPacket::UDP->decode($ipObj->{data});

  # decode sFlow
  my ($sFlowDatagram, $sFlowSamples, $error) = Net::sFlow::decode($udpObj->{data});

  # print errors
  foreach my $error (@{$errors}) {
    warn "$error";
  }

  # print sflow data

  print "===Datagram===\n";
  print "sFlow version: $sFlowDatagram->{sFlowVersion}\n";
  print "datagram sequence number: $sFlowDatagram->{datagramSequenceNumber}\n";

  foreach my $sFlowSample (@{$printSamples}) {
    print "\n";
    print "---Sample---\n";
    print "sample sequence number: $sFlowSample->{sampleSequenceNumber}\n";
  }



=head1 DESCRIPTION

The sFlow module provides a mechanism to parse and decode sFlow
datagrams. It supports sFlow version 2/4 (RFC 3176 -
http://www.ietf.org/rfc/rfc3176.txt) and sFlow version 5 (Memo -
http://sflow.org/sflow_version_5.txt).

The module's functionality is provided by a single (exportable)
function, L<decode|/decode>().


=head1 FUNCTIONS

=head2 X<decode>decode( UDP_PAYLOAD )
 
($datagram, $samples, $error) = Net::sFlow::decode($udp_data);

Returns a HASH reference containing the datagram data, 
an ARRAY reference with the sample data (each array element contains a HASH reference for one sample)
and in case of an error a reference to an ARRAY containing the error messages.

=head3 Return Values

=over 4
=item I<$datagram>


A HASH reference containing information about the sFlow datagram, with
the following keys:

  sFlowVersion
  AgentIpVersion
  AgentIp
  datagramSequenceNumber
  agentUptime
  samplesInPacket

In the case of sFlow v5, there is an additional key:

  subAgentId


=item I<$samples>


Reference to a list of HASH references, each one representing one
sample. Depending on the type, the hash contains the following additional keys:


In case of sFlow <= 4:

  sampleType
  sampleSequenceNumber
  sourceIdType
  sourceIdIndex

If it's a sFlow <= 4 flowsample you will get the following additional keys:

  samplingRate
  samplePool
  drops
  inputInterface
  outputInterface
  packetDataType
  extendedDataInSample

If it's a sFlow <= 4 countersample you will get these additional keys:

  counterSamplingInterval
  countersVersion

In case of sFlow >= 5 you will first get enterprise, format and length information:

  sampleTypeEnterprise
  sampleTypeFormat
  sampleLength

In case of a flowsample (enterprise == 0 and format == 1):

  sampleSequenceNumber
  sourceIdType
  sourceIdIndex
  samplingRate
  samplePool
  drops
  inputInterface
  outputInterface
  flowRecordsCount

If it's an expanded flowsample (enterprise == 0 and format == 3)
you will get these additional keys instead of inputInterface and outputInterface:

  inputInterfaceFormat
  inputInterfaceValue
  outputInterfaceFormat
  outputInterfaceValue

In case of a countersample (enterprise == 0 and format == 2) or
an expanded countersample (enterprise == 0 and format == 4):

  sampleSequenceNumber
  sourceIdType
  sourceIdIndex
  counterRecordsCount
  counterDataLength

Depending on what kind of samples the hardware is taking
you will get the following additional keys:


Header data:

  HEADERDATA
  HeaderProtocol
  HeaderFrameLength 
  HeaderStrippedLength
  HeaderSizeByte
  HeaderSizeBit

  HeaderEtherSrcMac
  HeaderEtherDestMac
  HeaderVer
  HeaderDatalen
  HeaderNexth
  HeaderProto
  HeaderSrcIP
  HeaderDestIP

  NoTransportLayer
  HeaderTCPSrcPort
  HeaderTCPDestPort
  HeaderUDPSrcPort
  HeaderUDPDestPort
  HeaderICMP

Ethernet frame data:

  ETHERNETFRAMEDATA
  EtherMacPacketlength
  EtherSrcMac
  EtherDestMac
  EtherPackettype

IPv4 data:

  IPv4DATA
  IPv4Packetlength
  IPv4NextHeaderProtocol
  IPv4srcIp
  IPv4destIp
  IPv4srcPort
  IPv4destPort
  IPv4tcpFlags
  IPv4tos

IPv6 data:

  IPv6DATA
  IPv6Packetlength
  IPv6NextHeaderProto
  IPv6srcIp
  IPv6destIp
  IPv6srcPort
  IPv6destPort
  IPv6tcpFlags
  IPv6Priority

Switch data:

  SWITCHDATA
  SwitchSrcVlan
  SwitchSrcPriority
  SwitchDestVlan
  SwitchDestPriority  

Router data:

  ROUTERDATA
  RouterIpVersionNextHopRouter
  RouterIpAddressNextHopRouter
  RouterSrcMask
  RouterDestMask

Gateway data:

  GATEWAYDATA
  GatewayIpVersionNextHopRouter (only in case of sFlow v5)
  GatewayIpAddressNextHopRouter (only in case of sFlow v5)
  GatewayAsRouter
  GatewayAsSource
  GatewayAsSourcePeer
  GatewayDestAsPathsCount

  GatewayDestAsPaths (arrayreference)
    each enty contains a hashreference:
      asPathSegmentType
      lengthAsList
      AsPath (arrayreference, asNumbers as entries)

  GatewayLengthCommunitiesList (added in sFlow v4)
  GatewayCommunities (arrayreference, added in sFlow v4)
    each enty contains a community (added in sFlow v4)

  localPref

User data:

  USERDATA
  UserSrcCharset (only in case of sFlow v5)
  UserLengthSrcString
  UserSrcString
  UserDestCharset (only in case of sFlow v5)
  UserLengthDestString
  UserDestString

Url data (added in sFlow v3):

  URLDATA
  UrlDirection
  UrlLength
  Url
  UrlHostLength (only in case of sFlow v5)
  UrlHost (only in case of sFlow v5)


The following keys can be only available in sFlow v5:

Mpls data:

  MPLSDATA
  MplsIpVersionNextHopRouter
  MplsIpAddressNextHopRouter
  MplsInLabesStackCount
  MplsInLabelStack (arrayreference containing MplsInLabels)
  MplsOutLabelStackCount
  MplsOutLabelStack (arrayreference containing MplsOutLabels)  

Nat data:

  NATDATA
  NatIpVersionSrcAddress
  NatSrcAddress
  NatIpVersionDestAddress
  NatDestAddress

Mpls tunnel:

  MPLSTUNNEL
  MplsTunnelLength
  MplsTunnelName
  MplsTunnelId
  MplsTunnelCosValue  

Mpls vc:

  MPLSVC
  MplsVcInstanceNameLength
  MplsVcInstanceName
  MplsVcId
  MplsVcLabelCosValue

Mpls fec:

  MPLSFEC
  MplsFtnDescrLength
  MplsFtnDescr
  MplsFtnMask

Mpls lpv fec:

  MPLSLPVFEC
  MplsFecAddrPrefixLength

Vlan tunnel:

  VLANTUNNEL
  VlanTunnelLayerStackCount
  VlanTunnelLayerStack (arrayreference containing VlanTunnelLayer entries)

The following keys are also available in sFlow < 5:

Counter generic:

  COUNTERGENERIC
  ifIndex
  ifType
  ifSpeed
  ifDirection
  ifAdminStatus
  ifOperStatus
  idInOctets
  ifInUcastPkts
  ifInMulticastPkts
  ifInBroadcastPkts
  idInDiscards
  ifInErrors
  ifInUnknownProtos
  ifOutOctets
  ifOutUcastPkts
  ifOutMulticastPkts
  ifOutBroadcastPkts
  ifOutDiscards
  ifOutErrors
  ifPromiscuousMode

Counter ethernet:

  COUNTERETHERNET
  dot3StatsAlignmentErrors
  dot3StatsFCSErrors
  dot3StatsSingleCollisionFrames
  dot3StatsMultipleCollisionFrames
  dot3StatsSQETestErrors
  dot3StatsDeferredTransmissions
  dot3StatsLateCollisions
  dot3StatsExcessiveCollisions
  dot3StatsInternalMacTransmitErrors
  dot3StatsCarrierSenseErrors
  dot3StatsFrameTooLongs
  dot3StatsInternalMacReceiveErrors
  dot3StatsSymbolErrors

Counter tokenring:

  COUNTERTOKENRING
  dot5StatsLineErrors
  dot5StatsBurstErrors
  dot5StatsACErrors
  dot5StatsAbortTransErrors
  dot5StatsInternalErrors
  dot5StatsLostFrameErrors
  dot5StatsReceiveCongestions
  dot5StatsFrameCopiedErrors
  dot5StatsTokenErrors
  dot5StatsSoftErrors
  dot5StatsHardErrors
  dot5StatsSignalLoss
  dot5StatsTransmitBeacons
  dot5StatsRecoverys
  dot5StatsLobeWires
  dot5StatsRemoves
  dot5StatsSingles
  dot5StatsFreqErrors

Counter vg:

  COUNTERVG
  dot12InHighPriorityFrames
  dot12InHighPriorityOctets
  dot12InNormPriorityFrames
  dot12InNormPriorityOctets
  dot12InIPMErrors
  dot12InOversizeFrameErrors
  dot12InDataErrors
  dot12InNullAddressedFrames
  dot12OutHighPriorityFrames
  dot12OutHighPriorityOctets
  dot12TransitionIntoTrainings
  dot12HCInHighPriorityOctets
  dot12HCInNormPriorityOctets
  dot12HCOutHighPriorityOctets

Counter vlan:

  COUNTERVLAN
  vlan_id
  octets
  ucastPkts
  multicastPkts
  broadcastPkts
  discards

Counter processor (only in sFlow v5):

  COUNTERPROCESSOR
  cpu5s
  cpu1m
  cpu5m
  memoryTotal
  memoryFree 


=item I<$error>

Reference to a list of error messages.

=back


=head1 CAVEATS

The L<decode|/decode> function will blindly attempt to decode the data
you provide. There are some tests for the appropriate values at various
places (where it is feasible to test - like enterprises,
formats, versionnumbers, etc.), but in general the GIGO principle still
stands: Garbage In / Garbage Out.


=head1 SEE ALSO

sFlow v4
http://www.ietf.org/rfc/rfc3176.txt

Format Diagram v4:
http://jasinska.de/sFlow/sFlowV4FormatDiagram/

sFlow v5
http://sflow.org/sflow_version_5.txt

Format Diagram v5:
http://jasinska.de/sFlow/sFlowV5FormatDiagram/

NetPacket
http://search.cpan.org/~atrak/NetPacket/

NetPacket::IPv6.pm modified
http://jasinska.de/sFlow/NetPacket/

Net::IP
http://search.cpan.org/~manu/Net-IP-1.25/IP.pm

Math::BigInt
http://search.cpan.org/~tels/Math-BigInt-1.77/lib/Math/BigInt.pm


=head1 AUTHOR

Elisa Jasinska <elisa.jasinska@ams-ix.net>


=head1 CONTACT

Please send comments or bug reports to <sflow@ams-ix.net>


=head1 COPYRIGHT

Copyright (c) 2006 AMS-IX B.V.

This package is free software and is provided "as is" without express 
or implied warranty.  It may be used, redistributed and/or modified 
under the terms of the Perl Artistic License (see
http://www.perl.com/perl/misc/Artistic.html)

=cut

